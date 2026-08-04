"""The threaded scanning engine.

A producer thread walks the feeder and hands addresses to a fixed pool of
worker threads through a bounded queue. Bounded matters: it means a /8 sweep
uses the same amount of memory as a /24, because the producer blocks instead
of racing ahead.

Each worker builds a :class:`ScanningSubject` and runs the selected fetchers
over it in order, short-circuiting the expensive ones when a host turns out
to be dead.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Sequence

from .config import Config
from .ranges import Feeder
from .subject import HostState, ScanResult, ScanningSubject

_SENTINEL = object()


@dataclass
class ScanStats:
    """Live counters for the status bar and the end-of-scan summary."""

    total: int = 0
    scanned: int = 0
    alive: int = 0
    with_ports: int = 0
    open_ports: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0
    aborted: bool = False

    @property
    def dead(self) -> int:
        return max(0, self.scanned - self.alive)

    @property
    def elapsed(self) -> float:
        end = self.finished_at or time.monotonic()
        return max(0.0, end - self.started_at) if self.started_at else 0.0

    @property
    def percent(self) -> int:
        if self.total <= 0:
            return 0
        return min(100, int(100.0 * self.scanned / self.total))

    @property
    def rate(self) -> float:
        """Hosts per second."""
        return self.scanned / self.elapsed if self.elapsed > 0.05 else 0.0

    def summary(self) -> str:
        mins, secs = divmod(int(self.elapsed), 60)
        duration = f"{mins}:{secs:02d}" if mins else f"{secs}s"
        return (
            f"{self.scanned} scanned in {duration} - "
            f"{self.alive} alive, {self.with_ports} with open ports, "
            f"{self.open_ports} open ports total"
        )


class Scanner:
    """Runs a feeder's addresses through a list of fetchers."""

    def __init__(
        self,
        feeder: Feeder,
        fetchers: Sequence,
        config: Config,
        on_result: Optional[Callable[[ScanResult], None]] = None,
        on_progress: Optional[Callable[[ScanStats], None]] = None,
        on_finished: Optional[Callable[[ScanStats], None]] = None,
        on_error: Optional[Callable[[str, Exception], None]] = None,
        display: str | None = None,
    ):
        self.feeder = feeder
        self.fetchers = list(fetchers)
        self.config = config
        self.on_result = on_result
        self.on_progress = on_progress
        self.on_finished = on_finished
        self.on_error = on_error

        self.stats = ScanStats()
        self._abort = threading.Event()
        self._done = threading.Event()
        self._lock = threading.Lock()
        self._queue: queue.Queue = queue.Queue(maxsize=1)
        self._workers: list[threading.Thread] = []
        self._producer: Optional[threading.Thread] = None
        self._runner: Optional[threading.Thread] = None
        self._index = 0

        self.max_threads = config.int_of("max_threads", 1, 2048)
        self.thread_delay = config.int_of("thread_delay_ms", 0, 10000) / 1000.0
        self.scan_dead = config.bool_of("scan_dead_hosts")
        # The GUI passes "all" and filters in the view, so changing the display
        # setting after a scan re-filters instantly instead of rescanning.
        self.display = str(display or config.get("display", "alive"))

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        """Begin scanning on a background thread and return immediately."""
        if self._runner and self._runner.is_alive():
            return
        self._runner = threading.Thread(target=self.run, name="scan-runner", daemon=True)
        self._runner.start()

    def run(self) -> ScanStats:
        """Scan synchronously; returns once every host has been processed."""
        self._abort.clear()
        self._done.clear()
        self.stats = ScanStats(total=self._safe_len(), started_at=time.monotonic())
        self._index = 0

        for fetcher in self.fetchers:
            try:
                fetcher.init(self.config)
            except Exception as exc:  # a broken fetcher must not kill the scan
                self._report_error(getattr(fetcher, "id", "?"), exc)

        self._queue = queue.Queue(maxsize=self.max_threads * 4)
        self._workers = [
            threading.Thread(target=self._worker, name=f"scan-{i}", daemon=True)
            for i in range(self.max_threads)
        ]
        for worker in self._workers:
            worker.start()

        self._producer = threading.Thread(target=self._produce, name="scan-feeder", daemon=True)
        self._producer.start()
        self._producer.join()

        for _ in self._workers:
            self._queue.put(_SENTINEL)
        for worker in self._workers:
            worker.join()

        for fetcher in self.fetchers:
            try:
                fetcher.cleanup()
            except Exception as exc:
                self._report_error(getattr(fetcher, "id", "?"), exc)

        self.stats.finished_at = time.monotonic()
        self.stats.aborted = self._abort.is_set()
        self._done.set()
        if self.on_finished:
            self.on_finished(self.stats)
        return self.stats

    def abort(self) -> None:
        self._abort.set()

    def join(self, timeout: float | None = None) -> bool:
        return self._done.wait(timeout)

    @property
    def aborted(self) -> bool:
        return self._abort.is_set()

    @property
    def running(self) -> bool:
        return bool(self._runner and self._runner.is_alive())

    # -- internals ---------------------------------------------------------
    def _safe_len(self) -> int:
        try:
            return len(self.feeder)
        except (TypeError, OverflowError):
            return 0

    def _produce(self) -> None:
        try:
            for address in self.feeder:
                if self._abort.is_set():
                    break
                while True:
                    try:
                        self._queue.put(address, timeout=0.2)
                        break
                    except queue.Full:
                        if self._abort.is_set():
                            return
                if self.thread_delay:
                    time.sleep(self.thread_delay)
        except Exception as exc:
            self._report_error("feeder", exc)

    def _worker(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.3)
            except queue.Empty:
                if self._abort.is_set():
                    return
                continue
            if item is _SENTINEL:
                return
            if self._abort.is_set():
                continue
            try:
                self._scan_one(item)
            except Exception as exc:
                self._report_error(str(item), exc)

    def _scan_one(self, address) -> None:
        subject = ScanningSubject(address, self.config)
        values: dict = {}

        for fetcher in self.fetchers:
            if self._abort.is_set():
                subject.abort()
                break
            needs_alive = getattr(fetcher, "requires_alive", True)
            if needs_alive and not subject.is_alive and not self.scan_dead:
                continue  # absent key renders as "not scanned"
            try:
                values[fetcher.id] = fetcher.scan(subject)
            except Exception as exc:
                values[fetcher.id] = None
                self._report_error(f"{fetcher.id}@{subject.ip}", exc)

        with self._lock:
            self._index += 1
            index = self._index
            self.stats.scanned += 1
            if subject.state >= HostState.ALIVE:
                self.stats.alive += 1
            if subject.state >= HostState.WITH_PORTS:
                self.stats.with_ports += 1
            ports = subject.get("open_ports") or []
            self.stats.open_ports += len(ports)
            snapshot = ScanStats(**vars(self.stats))

        if self.on_result and self._should_emit(subject.state):
            self.on_result(ScanResult(address, subject.state, values, index))
        if self.on_progress:
            self.on_progress(snapshot)

    def _should_emit(self, state: HostState) -> bool:
        if self.display == "all":
            return True
        if self.display == "ports":
            return state >= HostState.WITH_PORTS
        return state >= HostState.ALIVE

    def _report_error(self, where: str, exc: Exception) -> None:
        if self.on_error:
            try:
                self.on_error(where, exc)
            except Exception:
                pass
