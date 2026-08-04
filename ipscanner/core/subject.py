"""The per-host scanning context and its result."""

from __future__ import annotations

import enum
import socket
import threading
from typing import Any

from .ranges import IPAddress


class HostState(enum.IntEnum):
    """How a host ended up being classified. Ordering drives sort + colour."""

    UNKNOWN = 0
    DEAD = 1
    ALIVE = 2
    WITH_PORTS = 3

    @property
    def label(self) -> str:
        return {
            HostState.UNKNOWN: "Unknown",
            HostState.DEAD: "Dead",
            HostState.ALIVE: "Alive",
            HostState.WITH_PORTS: "Open ports",
        }[self]


class ScanningSubject:
    """Everything one host's fetchers need, plus a scratchpad they share.

    Fetchers run in order, so a later fetcher can reuse work an earlier one
    did (the ports fetcher publishes its open ports for the HTTP and NetBIOS
    fetchers, the ping fetcher publishes TTL and round-trip times, and so on).
    """

    __slots__ = ("address", "ip", "config", "params", "_state", "_lock",
                 "aborted", "adapter_ip")

    def __init__(self, address: IPAddress, config, adapter_ip: str | None = None):
        self.address = address
        self.ip = str(address)
        self.config = config
        self.params: dict[str, Any] = {}
        self._state = HostState.UNKNOWN
        self._lock = threading.Lock()
        self.aborted = False
        self.adapter_ip = adapter_ip

    # -- shared scratchpad -------------------------------------------------
    def set(self, key: str, value: Any) -> None:
        self.params[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.params.get(key, default)

    def has(self, key: str) -> bool:
        return key in self.params

    # -- state -------------------------------------------------------------
    @property
    def state(self) -> HostState:
        with self._lock:
            return self._state

    def promote(self, state: HostState) -> None:
        """Raise the host's state; never downgrade it."""
        with self._lock:
            if state > self._state:
                self._state = state

    def set_state(self, state: HostState) -> None:
        with self._lock:
            self._state = state

    # -- convenience -------------------------------------------------------
    @property
    def family(self) -> int:
        return socket.AF_INET6 if self.address.version == 6 else socket.AF_INET

    @property
    def is_alive(self) -> bool:
        return self.state >= HostState.ALIVE

    def abort(self) -> None:
        self.aborted = True

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ScanningSubject {self.ip} {self.state.name}>"


class ScanResult:
    """One row of the results table."""

    __slots__ = ("address", "ip", "state", "values", "index")

    def __init__(self, address: IPAddress, state: HostState,
                 values: dict[str, Any], index: int = 0):
        self.address = address
        self.ip = str(address)
        self.state = state
        self.values = values
        self.index = index

    def value(self, fetcher_id: str, default: Any = None) -> Any:
        return self.values.get(fetcher_id, default)

    def display(self, fetcher_id: str, not_available: str = "[n/a]",
                not_scanned: str = "[n/s]") -> str:
        """Render one cell.

        A missing key means the fetcher never ran (host was dead, or the scan
        was aborted); a present-but-empty value means it ran and found
        nothing. Those are different facts, so they get different text.
        """
        if fetcher_id not in self.values:
            return not_scanned
        value = self.values[fetcher_id]
        if value is None or value == "":
            return not_available
        if isinstance(value, (list, tuple)):
            return ", ".join(str(v) for v in value) if value else not_available
        return str(value)

    @property
    def sort_key(self) -> int:
        return int(self.address)

    def to_dict(self, not_available: str = "") -> dict[str, Any]:
        out = {"ip": self.ip, "state": self.state.label}
        out.update({k: v for k, v in self.values.items()})
        return out

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ScanResult {self.ip} {self.state.name} {self.values}>"
