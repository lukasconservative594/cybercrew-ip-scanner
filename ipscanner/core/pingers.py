"""Host liveness detection.

ICMP echo is the classic answer but it is also the one most likely to be
dropped - Windows Firewall blocks it by default, and plenty of networks
filter it at the edge. The ``combined`` pinger therefore escalates: ICMP,
then ARP for same-subnet targets (which no host firewall can refuse), then
TCP against a handful of common ports. That finds materially more live hosts
than ICMP alone, which matters a lot on an internal VAPT sweep.
"""

from __future__ import annotations

import errno
import os
import random
import socket
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from . import net
from .subject import ScanningSubject

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129

_IN_PROGRESS = {
    errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN, errno.EALREADY,
    10035,  # WSAEWOULDBLOCK
    10036,  # WSAEINPROGRESS
    10022,  # WSAEINVAL - Windows reports this for a repeat connect attempt
}

_REFUSED = {errno.ECONNREFUSED, errno.ECONNRESET, 10061, 10054}


@dataclass
class PingResult:
    """Outcome of one or more echo attempts against a single host."""

    sent: int = 0
    received: int = 0
    times: list[float] = field(default_factory=list)
    ttl: int = 0
    method: str = ""
    open_port: Optional[int] = None

    @property
    def alive(self) -> bool:
        return self.received > 0

    @property
    def average(self) -> float:
        return sum(self.times) / len(self.times) if self.times else 0.0

    @property
    def best(self) -> float:
        return min(self.times) if self.times else 0.0

    @property
    def worst(self) -> float:
        return max(self.times) if self.times else 0.0

    @property
    def packet_loss(self) -> int:
        if self.sent <= 0:
            return 100
        return int(round(100.0 * (self.sent - self.received) / self.sent))

    def merge(self, other: "PingResult") -> "PingResult":
        self.sent += other.sent
        self.received += other.received
        self.times.extend(other.times)
        self.ttl = self.ttl or other.ttl
        self.open_port = self.open_port or other.open_port
        if other.received and not self.method:
            self.method = other.method
        return self


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _echo_packet(kind: int, ident: int, seq: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", kind, 0, 0, ident, seq)
    chk = _checksum(header + payload)
    return struct.pack("!BBHHH", kind, 0, chk, ident, seq) + payload


class Pinger(ABC):
    """Determines whether a host answers."""

    id = "pinger"
    name = "Pinger"

    def __init__(self, timeout_ms: int = 1000, config=None):
        self.timeout_ms = max(50, int(timeout_ms))
        self.config = config

    @property
    def timeout(self) -> float:
        return self.timeout_ms / 1000.0

    @abstractmethod
    def ping(self, subject: ScanningSubject, count: int = 1) -> PingResult: ...

    def close(self) -> None:
        """Release any per-thread resources."""


class ICMPPinger(Pinger):
    """ICMP echo. Uses the unprivileged path available on each platform."""

    id = "icmp"
    name = "ICMP echo"

    def ping(self, subject: ScanningSubject, count: int = 1) -> PingResult:
        result = PingResult(method="ICMP")
        for seq in range(max(1, count)):
            if subject.aborted:
                break
            result.sent += 1
            reply = self._one(subject, seq)
            if reply.success:
                result.received += 1
                result.times.append(reply.rtt_ms)
                result.ttl = result.ttl or reply.ttl
        return result

    def _one(self, subject: ScanningSubject, seq: int) -> net.EchoReply:
        if net.IS_WINDOWS:
            if subject.address.version == 6:
                return net.windows_icmp6_echo(subject.ip, self.timeout_ms)
            return net.windows_icmp_echo(subject.ip, self.timeout_ms)
        return self._posix_echo(subject, seq)

    def _posix_echo(self, subject: ScanningSubject, seq: int) -> net.EchoReply:
        v6 = subject.address.version == 6
        family = socket.AF_INET6 if v6 else socket.AF_INET
        proto = socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP
        kind = ICMPV6_ECHO_REQUEST if v6 else ICMP_ECHO_REQUEST
        want = ICMPV6_ECHO_REPLY if v6 else ICMP_ECHO_REPLY

        sock = None
        for socktype in (socket.SOCK_DGRAM, socket.SOCK_RAW):
            try:
                sock = socket.socket(family, socktype, proto)
                break
            except OSError:
                sock = None
        if sock is None:
            return net.EchoReply(False)

        ident = os.getpid() & 0xFFFF
        try:
            sock.settimeout(self.timeout)
            packet = _echo_packet(kind, ident, seq, b"CyberCrewIPScanner")
            started = time.perf_counter()
            sock.sendto(packet, (subject.ip, 0))
            deadline = started + self.timeout
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    return net.EchoReply(False)
                sock.settimeout(remaining)
                data, addr = sock.recvfrom(2048)
                elapsed = (time.perf_counter() - started) * 1000.0
                if addr[0].split("%")[0] != subject.ip:
                    continue
                ttl = 0
                body = data
                if not v6 and len(data) >= 20 and (data[0] >> 4) == 4:
                    ihl = (data[0] & 0x0F) * 4
                    ttl = data[8]
                    body = data[ihl:]
                if len(body) < 8:
                    continue
                if body[0] != want:
                    continue
                _, r_seq = struct.unpack("!HH", body[4:8])
                if r_seq != seq:
                    continue
                return net.EchoReply(True, elapsed, ttl)
        except (socket.timeout, TimeoutError):
            return net.EchoReply(False)
        except OSError:
            return net.EchoReply(False)
        finally:
            sock.close()


class TCPPinger(Pinger):
    """Half-open style probe: an RST is just as good as a SYN/ACK.

    A refused connection proves the host exists, so we treat ECONNREFUSED as
    alive - that catches firewalled hosts that silently drop ICMP.
    """

    id = "tcp"
    name = "TCP probe"

    def __init__(self, timeout_ms: int = 1000, config=None, ports: list[int] | None = None):
        super().__init__(timeout_ms, config)
        if ports is None and config is not None:
            ports = config.get("ping_tcp_ports")
        self.ports = list(ports or [443, 80, 22, 445, 3389])

    def ping(self, subject: ScanningSubject, count: int = 1) -> PingResult:
        result = PingResult(method="TCP")
        per_port = max(0.15, self.timeout / max(1, len(self.ports)))
        for _ in range(max(1, count)):
            if subject.aborted:
                break
            result.sent += 1
            hit = False
            for port in self.ports:
                if subject.aborted:
                    break
                elapsed, state = self._probe(subject, port, per_port)
                if state == "open":
                    result.received += 1
                    result.times.append(elapsed)
                    result.open_port = result.open_port or port
                    hit = True
                    break
                if state == "refused":
                    result.received += 1
                    result.times.append(elapsed)
                    hit = True
                    break
            if not hit:
                continue
        return result

    def _probe(self, subject: ScanningSubject, port: int, timeout: float) -> tuple[float, str]:
        sock = socket.socket(subject.family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            started = time.perf_counter()
            code = sock.connect_ex((subject.ip, port))
            elapsed = (time.perf_counter() - started) * 1000.0
            if code == 0:
                return elapsed, "open"
            if code in _REFUSED:
                return elapsed, "refused"
            return elapsed, "no-reply"
        except OSError:
            return 0.0, "no-reply"
        finally:
            sock.close()


class UDPPinger(Pinger):
    """Send to a very likely closed port and listen for the ICMP unreachable."""

    id = "udp"
    name = "UDP probe"

    def ping(self, subject: ScanningSubject, count: int = 1) -> PingResult:
        result = PingResult(method="UDP")
        for _ in range(max(1, count)):
            if subject.aborted:
                break
            result.sent += 1
            port = random.randint(40000, 65000)
            sock = socket.socket(subject.family, socket.SOCK_DGRAM)
            try:
                sock.settimeout(self.timeout)
                started = time.perf_counter()
                sock.connect((subject.ip, port))
                sock.send(b"\x00" * 8)
                try:
                    sock.recv(1024)
                    result.received += 1
                    result.times.append((time.perf_counter() - started) * 1000.0)
                except (ConnectionResetError, ConnectionRefusedError):
                    # An ICMP port-unreachable came back: the host is up.
                    result.received += 1
                    result.times.append((time.perf_counter() - started) * 1000.0)
                except (socket.timeout, TimeoutError):
                    pass
            except OSError:
                pass
            finally:
                sock.close()
        return result


class ARPPinger(Pinger):
    """Layer-2 probe. Only meaningful for IPv4 targets on a local subnet,
    but on those it is both the fastest and the hardest to hide from."""

    id = "arp"
    name = "ARP probe"

    def ping(self, subject: ScanningSubject, count: int = 1) -> PingResult:
        result = PingResult(method="ARP")
        if subject.address.version != 4 or not is_local_subnet(subject.address):
            return result
        for _ in range(max(1, count)):
            if subject.aborted:
                break
            result.sent += 1
            started = time.perf_counter()
            mac = self._resolve(subject.ip)
            if mac:
                result.received += 1
                result.times.append((time.perf_counter() - started) * 1000.0)
                subject.set("mac", mac)
                break
        return result

    @staticmethod
    def _resolve(ip: str) -> Optional[str]:
        if net.IS_WINDOWS:
            mac = net.windows_send_arp(ip)
            if mac:
                return mac
        # Nudge the stack so the neighbour cache gets populated, then read it.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(0.25)
            sock.sendto(b"\x00", (ip, 33435))
        except OSError:
            pass
        finally:
            sock.close()
        return net.arp_table_lookup(ip)


class CombinedPinger(Pinger):
    """Escalating strategy - the default, and the one that finds the most hosts."""

    id = "combined"
    name = "Combined (ICMP + ARP + TCP)"

    def __init__(self, timeout_ms: int = 1000, config=None):
        super().__init__(timeout_ms, config)
        self.icmp = ICMPPinger(timeout_ms, config)
        self.arp = ARPPinger(min(timeout_ms, 800), config)
        self.tcp = TCPPinger(timeout_ms, config)

    def ping(self, subject: ScanningSubject, count: int = 1) -> PingResult:
        result = self.icmp.ping(subject, count)
        if result.alive or subject.aborted:
            return result

        if subject.address.version == 4 and is_local_subnet(subject.address):
            arp = self.arp.ping(subject, 1)
            if arp.alive:
                return result.merge(arp)

        if not subject.aborted:
            tcp = self.tcp.ping(subject, 1)
            if tcp.alive:
                return result.merge(tcp)
        return result


_LOCAL_NETWORKS: list = []
_LOCAL_LOADED = False


def local_networks() -> list:
    """Cached list of networks directly attached to this machine."""
    global _LOCAL_LOADED
    if not _LOCAL_LOADED:
        nets = []
        for iface in net.local_interfaces(include_ipv6=True):
            network = iface.network
            if network is not None:
                nets.append(network)
        _LOCAL_NETWORKS.clear()
        _LOCAL_NETWORKS.extend(nets)
        _LOCAL_LOADED = True
    return _LOCAL_NETWORKS


def refresh_local_networks() -> None:
    global _LOCAL_LOADED
    _LOCAL_LOADED = False


def is_local_subnet(address) -> bool:
    for network in local_networks():
        try:
            if address in network:
                return True
        except TypeError:
            continue
    return False


PINGERS: dict[str, type[Pinger]] = {
    CombinedPinger.id: CombinedPinger,
    ICMPPinger.id: ICMPPinger,
    TCPPinger.id: TCPPinger,
    UDPPinger.id: UDPPinger,
    ARPPinger.id: ARPPinger,
}


def create_pinger(config) -> Pinger:
    """Build the pinger named by ``ping_method`` in the config."""
    method = str(config.get("ping_method", "combined")).lower()
    cls = PINGERS.get(method, CombinedPinger)
    return cls(config.int_of("ping_timeout_ms", 50, 60000), config)
