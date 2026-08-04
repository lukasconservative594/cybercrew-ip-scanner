"""MAC address vendor lookup.

Ships with a curated table so vendor names work offline out of the box, and
can pull the full IEEE registry on demand. A downloaded registry always wins
over the built-in table.
"""

from __future__ import annotations

import csv
import gzip
import io
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from ..data.oui_builtin import OUI_CLEAN, normalise
from .config import user_config_dir

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

_lock = threading.Lock()
_downloaded: dict[str, str] = {}
_bundled: dict[str, str] = {}
_loaded = False

#: The IEEE registry records the legal registrant, which is often not the name
#: you care about: 08:00:27 is "PCS Systemtechnik GmbH", but what you actually
#: want to know is that the host is a VirtualBox guest. These hints are
#: appended to the registrant name rather than replacing it.
PLATFORM_HINTS: dict[str, str] = {
    "000569": "VMware", "000C29": "VMware", "001C14": "VMware", "005056": "VMware",
    "080027": "VirtualBox", "0A0027": "VirtualBox",
    "00155D": "Hyper-V",
    "525400": "QEMU/KVM", "5254AB": "QEMU/KVM",
    "00163E": "Xen",
    "001C42": "Parallels",
    "0242AC": "Docker",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "28CDC1": "Raspberry Pi", "D83ADD": "Raspberry Pi", "2CCF67": "Raspberry Pi",
}


def platform_hint(mac: str) -> Optional[str]:
    """Virtualisation or single-board-computer hint for a MAC, if any."""
    digits = normalise((mac or "").replace(":", "").replace("-", "").replace(".", ""))
    return PLATFORM_HINTS.get(digits[:6]) if len(digits) >= 6 else None


def database_path() -> Path:
    """Where a user-triggered registry update is stored."""
    return user_config_dir() / "oui.csv"


def bundled_path() -> Path:
    """The gzipped registry shipped inside the package."""
    return Path(__file__).resolve().parent.parent / "data" / "oui.csv.gz"


def _ensure_loaded() -> None:
    """Load the vendor tables once, newest source first."""
    global _loaded
    with _lock:
        if _loaded:
            return
        _loaded = True

        bundled = bundled_path()
        if bundled.exists():
            try:
                with gzip.open(bundled, "rt", encoding="utf-8", errors="ignore",
                               newline="") as fh:
                    for prefix, vendor in _parse_csv(fh):
                        _bundled[prefix] = vendor
            except (OSError, EOFError, gzip.BadGzipFile):
                _bundled.clear()

        path = database_path()
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore", newline="") as fh:
                for prefix, vendor in _parse_csv(fh):
                    _downloaded[prefix] = vendor
        except OSError:
            _downloaded.clear()


def _parse_csv(stream) -> list[tuple[str, str]]:
    """Read either the IEEE layout or our own two-column format."""
    rows: list[tuple[str, str]] = []
    reader = csv.reader(stream)
    for row in reader:
        if len(row) >= 3 and row[0].strip().upper().startswith("MA-"):
            prefix, vendor = normalise(row[1]), row[2].strip()
        elif len(row) >= 2:
            prefix, vendor = normalise(row[0]), row[1].strip()
        else:
            continue
        if len(prefix) == 6 and vendor and vendor.lower() != "organization name":
            rows.append((prefix, vendor))
    return rows


def lookup(mac: str) -> Optional[str]:
    """Vendor for a MAC address, or None if it is unknown."""
    if not mac:
        return None
    digits = normalise(mac.replace(":", "").replace("-", "").replace(".", ""))
    if len(digits) < 6:
        return None

    _ensure_loaded()
    vendor = _downloaded.get(digits) or _bundled.get(digits) or OUI_CLEAN.get(digits)
    hint = PLATFORM_HINTS.get(digits)
    if vendor:
        if hint and hint.split("/")[0].lower() not in vendor.lower():
            return f"{vendor} ({hint})"
        return vendor
    if hint:
        return hint

    # Bit 1 of the first octet marks a locally administered address - phones
    # and modern laptops randomise these, so there is no vendor to find.
    try:
        first = int(digits[:2], 16)
    except ValueError:
        return None
    if first & 0x02:
        return "(randomised / locally administered)"
    return None


def is_randomised(mac: str) -> bool:
    digits = normalise(mac or "")
    if len(digits) < 2:
        return False
    try:
        return bool(int(digits[:2], 16) & 0x02)
    except ValueError:
        return False


def entry_count() -> int:
    _ensure_loaded()
    return len(_downloaded) or len(_bundled) or len(OUI_CLEAN)


def using_full_registry() -> bool:
    _ensure_loaded()
    return bool(_downloaded or _bundled)


def source_description() -> str:
    _ensure_loaded()
    if _downloaded:
        return f"IEEE registry, downloaded ({len(_downloaded)} prefixes)"
    if _bundled:
        return f"IEEE registry, bundled ({len(_bundled)} prefixes)"
    return f"built-in table ({len(OUI_CLEAN)} prefixes)"


def update_from_ieee(progress: Optional[Callable[[str], None]] = None,
                     timeout: int = 60) -> tuple[bool, str]:
    """Download the IEEE MA-L registry. Returns (ok, message)."""
    global _loaded

    def say(message: str) -> None:
        if progress:
            try:
                progress(message)
            except Exception:
                pass

    say("Downloading IEEE OUI registry...")
    request = urllib.request.Request(
        IEEE_OUI_URL, headers={"User-Agent": "CyberCrewIPScanner/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, f"Download failed: {exc}"

    try:
        text = payload.decode("utf-8", errors="ignore")
        rows = _parse_csv(io.StringIO(text))
    except Exception as exc:
        return False, f"Could not parse the registry: {exc}"

    if len(rows) < 1000:
        return False, "The downloaded file did not look like the IEEE registry."

    path = database_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerows(rows)
    except OSError as exc:
        return False, f"Could not save the database: {exc}"

    with _lock:
        _downloaded.clear()
        _downloaded.update(dict(rows))
        _loaded = True

    say(f"Stored {len(rows)} vendor prefixes.")
    return True, f"MAC vendor database updated: {len(rows)} prefixes."
