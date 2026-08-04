"""Persisted user settings.

Portable by design: if a ``config.json`` (or an empty ``portable.txt`` marker)
sits next to the executable, settings live there so the whole tool can be
copied onto a USB stick and carried between machines. Otherwise we fall back
to the usual per-user config directory.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

from .. import APP_ID

DEFAULTS: dict[str, Any] = {
    # --- scanning ---------------------------------------------------------
    "max_threads": 100,
    "thread_delay_ms": 0,
    "skip_broadcast": True,
    "scan_dead_hosts": False,

    # --- pinging ----------------------------------------------------------
    "ping_method": "combined",       # combined | icmp | tcp | udp | arp
    "ping_timeout_ms": 1000,
    "ping_count": 2,
    "ping_tcp_ports": [443, 80, 22, 445, 3389],

    # --- ports ------------------------------------------------------------
    "ports": "20-23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,"
             "1723,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017",
    "port_timeout_ms": 1200,
    "port_batch": 128,
    "detect_filtered_ports": False,
    "grab_banners": True,

    # --- fetchers ---------------------------------------------------------
    "selected_fetchers": [
        "ip", "ping", "hostname", "ports", "mac", "vendor", "http", "netbios",
    ],

    # --- display ----------------------------------------------------------
    "display": "alive",              # all | alive | ports
    "not_available_text": "[n/a]",
    "not_scanned_text": "[n/s]",
    "hostname_timeout_ms": 3000,
    "web_detect_ports": [80, 443, 8080, 8443, 8000],

    # --- user data --------------------------------------------------------
    "comments": {},
    "favorites": {},
    "last_range": {"from": "", "to": ""},
    "openers": [],
    "column_widths": {},
    "window_geometry": "",
}


def _frozen_dir() -> Path:
    """Directory holding the running executable (or the project root)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def _portable_path() -> Path | None:
    base = _frozen_dir()
    if (base / "portable.txt").exists() or (base / "config.json").exists():
        return base / "config.json"
    return None


def user_config_dir() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return root / APP_ID


def config_path() -> Path:
    portable = _portable_path()
    return portable if portable else user_config_dir() / "config.json"


class Config:
    """Thread-safe dict-like settings store backed by a JSON file."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else config_path()
        self._lock = threading.RLock()
        self._data: dict[str, Any] = copy.deepcopy(DEFAULTS)
        self.load()

    # -- persistence -------------------------------------------------------
    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                stored = json.load(fh)
            if isinstance(stored, dict):
                with self._lock:
                    for key, value in stored.items():
                        if key in DEFAULTS:
                            self._data[key] = value
        except (OSError, json.JSONDecodeError):
            pass

    def save(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".json.tmp")
            with self._lock:
                snapshot = copy.deepcopy(self._data)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
            return True
        except OSError:
            return False

    def reset(self) -> None:
        with self._lock:
            self._data = copy.deepcopy(DEFAULTS)

    # -- access ------------------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            if key in self._data:
                return self._data[key]
        return DEFAULTS.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def update(self, values: dict[str, Any]) -> None:
        with self._lock:
            self._data.update(values)

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data)

    def __getitem__(self, key: str) -> Any:
        return self.get(key)

    def __setitem__(self, key: str, value: Any) -> None:
        self.set(key, value)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._data

    # -- typed convenience -------------------------------------------------
    def int_of(self, key: str, minimum: int | None = None, maximum: int | None = None) -> int:
        try:
            value = int(self.get(key))
        except (TypeError, ValueError):
            value = int(DEFAULTS.get(key, 0))
        if minimum is not None:
            value = max(minimum, value)
        if maximum is not None:
            value = min(maximum, value)
        return value

    def bool_of(self, key: str) -> bool:
        return bool(self.get(key))

    @property
    def is_portable(self) -> bool:
        return _portable_path() is not None
