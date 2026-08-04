"""NetBIOS node status (NBSTAT) fetchers.

A single UDP query to port 137 returns the machine name, the workgroup or
domain it belongs to, the currently logged-on user and the adapter MAC -
without authenticating. On a Windows estate this is often the fastest way to
map who is who.
"""

from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from ..core.subject import ScanningSubject
from .base import Fetcher, register

NBSTAT_KEY = "netbios"
NBNS_PORT = 137


@dataclass
class NetBIOSInfo:
    computer: str = ""
    workgroup: str = ""
    user: str = ""
    mac: str = ""
    names: list[tuple[str, int, bool]] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.computer or self.workgroup or self.user)


def _encode_name(name: str = "*") -> bytes:
    """First-level NetBIOS name encoding (each nibble becomes a letter)."""
    padded = name.ljust(16, "\x00")[:16].encode("ascii", "replace")
    out = bytearray()
    for byte in padded:
        out.append(ord("A") + (byte >> 4))
        out.append(ord("A") + (byte & 0x0F))
    return bytes(out)


def _build_query() -> tuple[bytes, int]:
    trn_id = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", trn_id, 0x0000, 1, 0, 0, 0)
    question = b"\x20" + _encode_name("*") + b"\x00" + struct.pack("!HH", 0x0021, 0x0001)
    return header + question, trn_id


def query_netbios(ip: str, timeout: float = 1.0) -> Optional[NetBIOSInfo]:
    """Send an NBSTAT node status request and parse the reply."""
    packet, trn_id = _build_query()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, NBNS_PORT))
        while True:
            data, addr = sock.recvfrom(2048)
            if addr[0] != ip:
                continue
            if len(data) < 57:
                return None
            if struct.unpack("!H", data[0:2])[0] != trn_id:
                continue
            return _parse_reply(data)
    except (socket.timeout, TimeoutError, OSError):
        return None
    finally:
        sock.close()


def _parse_reply(data: bytes) -> Optional[NetBIOSInfo]:
    # header(12) + encoded name(34) + type(2) + class(2) + ttl(4) + rdlength(2)
    offset = 12 + 34 + 2 + 2 + 4 + 2
    if len(data) <= offset:
        return None
    count = data[offset]
    offset += 1

    info = NetBIOSInfo()
    for _ in range(count):
        if offset + 18 > len(data):
            break
        raw = data[offset:offset + 15]
        suffix = data[offset + 15]
        flags = struct.unpack("!H", data[offset + 16:offset + 18])[0]
        offset += 18

        name = raw.decode("latin-1", errors="ignore").strip().strip("\x00").strip()
        if not name:
            continue
        is_group = bool(flags & 0x8000)
        info.names.append((name, suffix, is_group))

        if is_group:
            if suffix in (0x00, 0x1E) and not info.workgroup:
                info.workgroup = name
        else:
            if suffix == 0x00 and not info.computer:
                info.computer = name
            elif suffix == 0x20 and not info.computer:
                info.computer = name
            elif suffix == 0x03:
                info.user = name

    # A 0x03 entry echoing the machine name is the messenger service, not a user.
    if info.user and info.user.upper() == info.computer.upper():
        info.user = ""

    if offset + 6 <= len(data):
        mac = ":".join(f"{b:02X}" for b in data[offset:offset + 6])
        if mac != "00:00:00:00:00:00":
            info.mac = mac
    return info or None


def _info_for(subject: ScanningSubject, timeout: float) -> Optional[NetBIOSInfo]:
    """Query once per host and cache it for the sibling fetchers."""
    if subject.has(NBSTAT_KEY):
        return subject.get(NBSTAT_KEY)
    info = None
    if subject.address.version == 4:
        info = query_netbios(subject.ip, timeout)
    subject.set(NBSTAT_KEY, info)
    if info and info.mac and not subject.has("mac"):
        subject.set("mac", info.mac)
    return info


class _NetBIOSFetcher(Fetcher):
    order = 60

    def init(self, config) -> None:
        super().init(config)
        self.timeout = max(0.3, config.int_of("ping_timeout_ms", 50, 60000) / 1000.0)


@register
class NetBIOSNameFetcher(_NetBIOSFetcher):
    id = "netbios"
    name = "NetBIOS Name"
    description = "Computer name reported over NetBIOS."
    order = 60
    width = 150

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        info = _info_for(subject, self.timeout)
        return info.computer if info and info.computer else None


@register
class NetBIOSGroupFetcher(_NetBIOSFetcher):
    id = "netbios_group"
    name = "Workgroup"
    description = "NetBIOS workgroup or domain name."
    order = 61
    width = 130

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        info = _info_for(subject, self.timeout)
        return info.workgroup if info and info.workgroup else None


@register
class NetBIOSUserFetcher(_NetBIOSFetcher):
    id = "netbios_user"
    name = "Logged-in User"
    description = "User currently logged on, if the host advertises it."
    order = 62
    width = 130

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        info = _info_for(subject, self.timeout)
        return info.user if info and info.user else None
