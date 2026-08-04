"""IP range parsing and the feeders that drive a scan.

A *feeder* is anything that can enumerate the addresses to scan. Feeders are
lazy iterables so that a /8 sweep does not materialise 16M objects up front.
"""

from __future__ import annotations

import ipaddress
import random
import re
import socket
from abc import ABC, abstractmethod
from typing import Iterator, Sequence

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class RangeError(ValueError):
    """Raised when user supplied range text cannot be understood."""


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------

def parse_ip(text: str) -> IPAddress:
    text = (text or "").strip()
    if not text:
        raise RangeError("Empty address")
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        pass
    # Fall back to DNS resolution so hostnames work anywhere an IP does.
    try:
        info = socket.getaddrinfo(text, None)
        return ipaddress.ip_address(info[0][4][0].split("%")[0])
    except (socket.gaierror, ValueError, IndexError) as exc:
        raise RangeError(f"Cannot resolve '{text}'") from exc


def netmask_to_prefix(mask: str) -> int:
    """Accept '255.255.255.0', '/24' or '24' and return the prefix length."""
    mask = (mask or "").strip().lstrip("/")
    if not mask:
        raise RangeError("Empty netmask")
    if mask.isdigit():
        n = int(mask)
        if 0 <= n <= 128:
            return n
        raise RangeError(f"Invalid prefix length: {mask}")
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError as exc:
        raise RangeError(f"Invalid netmask: {mask}") from exc


def range_of_network(ip: IPAddress, prefix: int) -> tuple[IPAddress, IPAddress]:
    """The first/last address of the network containing *ip*."""
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except ValueError as exc:
        raise RangeError(str(exc)) from exc
    return net.network_address, net.broadcast_address


def parse_range_text(text: str) -> tuple[IPAddress, IPAddress]:
    """Parse the many shapes a range can take into an inclusive start/end pair.

    Understands: ``a.b.c.d``, ``a.b.c.d-e.f.g.h``, ``a.b.c.1-254``,
    ``a.b.c.d/24``, ``a.b.c.d/255.255.255.0`` and ``a.b.c.*``.
    """
    text = (text or "").strip()
    if not text:
        raise RangeError("Empty range")

    if "/" in text:
        addr, _, mask = text.partition("/")
        ip = parse_ip(addr)
        return range_of_network(ip, netmask_to_prefix(mask))

    if "*" in text:
        # 10.0.*.* style wildcard
        octets = text.split(".")
        low = [o if o != "*" else "0" for o in octets]
        high = [o if o != "*" else "255" for o in octets]
        return parse_ip(".".join(low)), parse_ip(".".join(high))

    if "-" in text and not text.count(":") > 1:
        left, _, right = text.partition("-")
        left, right = left.strip(), right.strip()
        start = parse_ip(left)
        if "." not in right and right.isdigit() and start.version == 4:
            # 192.168.1.1-254 shorthand
            prefix = left.rsplit(".", 1)[0]
            end = parse_ip(f"{prefix}.{right}")
        else:
            end = parse_ip(right)
        return start, end

    ip = parse_ip(text)
    return ip, ip


def parse_ports(text: str) -> list[int]:
    """Parse '80,443,1-1024,8080' into a sorted, de-duplicated port list."""
    ports: set[int] = set()
    for chunk in re.split(r"[,\s;]+", (text or "").strip()):
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError as exc:
                raise RangeError(f"Invalid port range: {chunk}") from exc
            if lo > hi:
                lo, hi = hi, lo
            if lo < 1 or hi > 65535:
                raise RangeError(f"Port out of range: {chunk}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(chunk)
            except ValueError as exc:
                raise RangeError(f"Invalid port: {chunk}") from exc
            if not 1 <= p <= 65535:
                raise RangeError(f"Port out of range: {p}")
            ports.add(p)
    return sorted(ports)


def format_ports(ports: Sequence[int]) -> str:
    """Collapse a port list back into compact '1-3,80,443' notation."""
    if not ports:
        return ""
    out: list[str] = []
    ordered = sorted(set(ports))
    start = prev = ordered[0]
    for p in ordered[1:]:
        if p == prev + 1:
            prev = p
            continue
        out.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = p
    out.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(out)


def is_broadcastish(ip: IPAddress) -> bool:
    """True for addresses ending in .0 or .255 (likely network/broadcast)."""
    if ip.version != 4:
        return False
    last = int(ip) & 0xFF
    return last in (0, 255)


# --------------------------------------------------------------------------
# Feeders
# --------------------------------------------------------------------------

class Feeder(ABC):
    """Enumerates the addresses a scan should visit."""

    id: str = "feeder"
    name: str = "Feeder"

    @abstractmethod
    def __iter__(self) -> Iterator[IPAddress]: ...

    @abstractmethod
    def __len__(self) -> int: ...

    @property
    @abstractmethod
    def info(self) -> str:
        """Short human readable description, shown in the title bar."""


class RangeFeeder(Feeder):
    """Every address between two endpoints, inclusive."""

    id = "range"
    name = "IP Range"

    def __init__(self, start: IPAddress | str, end: IPAddress | str,
                 skip_broadcast: bool = False):
        self.start = parse_ip(start) if isinstance(start, str) else start
        self.end = parse_ip(end) if isinstance(end, str) else end
        if self.start.version != self.end.version:
            raise RangeError("Start and end must be the same IP version")
        if int(self.start) > int(self.end):
            self.start, self.end = self.end, self.start
        self.skip_broadcast = skip_broadcast

    def __iter__(self) -> Iterator[IPAddress]:
        cls = type(self.start)
        for value in range(int(self.start), int(self.end) + 1):
            ip = cls(value)
            if self.skip_broadcast and is_broadcastish(ip):
                continue
            yield ip

    def __len__(self) -> int:
        total = int(self.end) - int(self.start) + 1
        if self.skip_broadcast and self.start.version == 4:
            lo, hi = int(self.start), int(self.end)
            total -= _count_last_octet(lo, hi, 0) + _count_last_octet(lo, hi, 255)
        return max(0, total)

    @property
    def info(self) -> str:
        return f"{self.start} - {self.end}"

    @classmethod
    def from_text(cls, text: str, skip_broadcast: bool = False) -> "RangeFeeder":
        start, end = parse_range_text(text)
        return cls(start, end, skip_broadcast)


def _count_last_octet(lo: int, hi: int, wanted: int) -> int:
    """How many addresses in [lo, hi] have *wanted* as their last octet."""
    if hi < lo:
        return 0
    first = lo + ((wanted - (lo & 0xFF)) % 256)
    if first > hi:
        return 0
    return (hi - first) // 256 + 1


class ListFeeder(Feeder):
    """An explicit list of addresses."""

    id = "list"
    name = "IP List"

    def __init__(self, addresses: Sequence[IPAddress | str], label: str = "IP list"):
        self.addresses = [parse_ip(a) if isinstance(a, str) else a for a in addresses]
        self.label = label

    def __iter__(self) -> Iterator[IPAddress]:
        return iter(self.addresses)

    def __len__(self) -> int:
        return len(self.addresses)

    @property
    def info(self) -> str:
        return f"{self.label} ({len(self.addresses)} hosts)"


class FileFeeder(ListFeeder):
    """Addresses read from a text file, one entry per line.

    Blank lines and ``#`` comments are ignored; each line may itself be a
    range, CIDR or wildcard.
    """

    id = "file"
    name = "IP List File"

    def __init__(self, path: str, skip_broadcast: bool = False):
        addresses: list[IPAddress] = []
        seen: set[str] = set()
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                try:
                    start, end = parse_range_text(line)
                except RangeError:
                    continue
                for ip in RangeFeeder(start, end, skip_broadcast):
                    key = str(ip)
                    if key not in seen:
                        seen.add(key)
                        addresses.append(ip)
        super().__init__(addresses, label=path)
        self.path = path


class RandomFeeder(Feeder):
    """A random sample of addresses from a network - handy for spot checks."""

    id = "random"
    name = "Random"

    def __init__(self, base: IPAddress | str, prefix: int, count: int,
                 skip_broadcast: bool = False, seed: int | None = None):
        self.base = parse_ip(base) if isinstance(base, str) else base
        self.prefix = prefix
        self.count = max(1, count)
        self.skip_broadcast = skip_broadcast
        self._rng = random.Random(seed)
        self.start, self.end = range_of_network(self.base, prefix)

    def __iter__(self) -> Iterator[IPAddress]:
        cls = type(self.start)
        lo, hi = int(self.start), int(self.end)
        produced = 0
        guard = 0
        limit = self.count * 50 + 1000
        while produced < self.count and guard < limit:
            guard += 1
            ip = cls(self._rng.randint(lo, hi))
            if self.skip_broadcast and is_broadcastish(ip):
                continue
            produced += 1
            yield ip

    def __len__(self) -> int:
        return self.count

    @property
    def info(self) -> str:
        return f"{self.count} random in {self.base}/{self.prefix}"
