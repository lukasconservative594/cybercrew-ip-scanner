"""Fetcher plugin contract and registry.

A fetcher is one column in the results table and one piece of work per host.
Adding a new one is the whole extension story: subclass :class:`Fetcher`,
decorate it with :func:`register`, and it shows up in the UI, the exports and
the CLI automatically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable, Sequence

from ..core.config import Config
from ..core.subject import ScanningSubject

REGISTRY: dict[str, type["Fetcher"]] = {}


class Fetcher(ABC):
    """One unit of per-host information gathering."""

    #: stable identifier - used in config, exports and the shared scratchpad
    id: str = "fetcher"
    #: column heading
    name: str = "Fetcher"
    #: shown as a tooltip / in the fetcher chooser
    description: str = ""
    #: skip this fetcher for hosts that did not answer
    requires_alive: bool = True
    #: fetchers always run in this order regardless of column order
    order: int = 50
    #: preferred column width in pixels
    width: int = 120
    #: right-align and sort numerically
    numeric: bool = False

    def __init__(self) -> None:
        self.config: Config | None = None

    def init(self, config: Config) -> None:
        """Called once before a scan starts."""
        self.config = config

    @abstractmethod
    def scan(self, subject: ScanningSubject) -> Any:
        """Gather this fetcher's value for one host.

        Return ``None`` to mean "ran, found nothing". Must be safe to call
        from many threads at once.
        """

    def cleanup(self) -> None:
        """Called once after a scan finishes."""

    # -- helpers for subclasses -------------------------------------------
    def setting(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default) if self.config else default

    def int_setting(self, key: str, minimum: int | None = None,
                    maximum: int | None = None) -> int:
        if self.config:
            return self.config.int_of(key, minimum, maximum)
        return 0

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} id={self.id}>"


def register(cls: type[Fetcher]) -> type[Fetcher]:
    """Class decorator that adds a fetcher to the global registry."""
    REGISTRY[cls.id] = cls
    return cls


def available() -> list[type[Fetcher]]:
    """All known fetcher classes, in canonical run order."""
    return sorted(REGISTRY.values(), key=lambda c: (c.order, c.name))


def create(ids: Sequence[str]) -> list[Fetcher]:
    """Instantiate the named fetchers, sorted into canonical run order.

    Unknown ids are ignored, and ``ip`` is always present so every result has
    something to key on.
    """
    wanted: list[str] = []
    for fid in ids:
        if fid in REGISTRY and fid not in wanted:
            wanted.append(fid)
    if "ip" in REGISTRY and "ip" not in wanted:
        wanted.insert(0, "ip")
    classes = [REGISTRY[f] for f in wanted]
    classes.sort(key=lambda c: (c.order, c.name))
    return [cls() for cls in classes]


def default_ids() -> list[str]:
    return ["ip", "ping", "hostname", "ports", "mac", "vendor", "http", "netbios"]
