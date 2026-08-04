"""Address, liveness and naming fetchers."""

from __future__ import annotations

import socket
from typing import Optional

from ..core import pingers
from ..core.subject import HostState, ScanningSubject
from .base import Fetcher, register

PING_KEY = "ping_result"


@register
class IPFetcher(Fetcher):
    id = "ip"
    name = "IP"
    description = "The scanned address."
    requires_alive = False
    order = 0
    width = 140

    def scan(self, subject: ScanningSubject) -> str:
        return subject.ip


@register
class PingFetcher(Fetcher):
    """Decides whether the host is alive; everything else depends on it."""

    id = "ping"
    name = "Ping"
    description = "Round-trip time in milliseconds."
    requires_alive = False
    order = 10
    width = 70
    numeric = True

    def init(self, config) -> None:
        super().init(config)
        self.pinger = pingers.create_pinger(config)
        self.count = config.int_of("ping_count", 1, 20)
        pingers.refresh_local_networks()

    def scan(self, subject: ScanningSubject) -> Optional[int]:
        result = self.pinger.ping(subject, self.count)
        subject.set(PING_KEY, result)
        if result.alive:
            subject.promote(HostState.ALIVE)
            if result.open_port:
                subject.set("ping_open_port", result.open_port)
            return int(round(result.average))
        subject.set_state(HostState.DEAD)
        return None

    def cleanup(self) -> None:
        try:
            self.pinger.close()
        except Exception:
            pass


@register
class TTLFetcher(Fetcher):
    """TTL hints at the remote OS and how many hops away it is."""

    id = "ttl"
    name = "TTL"
    description = "IP time-to-live of the echo reply (hints at the remote OS)."
    order = 15
    width = 60
    numeric = True

    def scan(self, subject: ScanningSubject) -> Optional[int]:
        result = subject.get(PING_KEY)
        ttl = getattr(result, "ttl", 0) if result else 0
        return ttl or None


@register
class OSGuessFetcher(Fetcher):
    """Very rough OS family guess from the TTL the host replied with."""

    id = "osguess"
    name = "OS Guess"
    description = "Coarse OS family inferred from the reply TTL."
    order = 16
    width = 90

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        result = subject.get(PING_KEY)
        ttl = getattr(result, "ttl", 0) if result else 0
        if not ttl:
            return None
        # Hosts start at a round number and lose one per hop.
        for initial, label in ((64, "Linux/Unix"), (128, "Windows"), (255, "Network device")):
            if 0 < ttl <= initial and initial - ttl <= 32:
                hops = initial - ttl
                return f"{label} (~{hops} hops)" if hops else label
        return None


@register
class PacketLossFetcher(Fetcher):
    id = "loss"
    name = "Loss %"
    description = "Percentage of echo requests that went unanswered."
    requires_alive = False
    order = 17
    width = 60
    numeric = True

    def scan(self, subject: ScanningSubject) -> Optional[int]:
        result = subject.get(PING_KEY)
        if not result or not getattr(result, "sent", 0):
            return None
        return result.packet_loss


@register
class HostnameFetcher(Fetcher):
    """Reverse DNS. Slow on hosts with no PTR record, hence its own timeout."""

    id = "hostname"
    name = "Hostname"
    description = "Reverse DNS name."
    order = 20
    width = 200

    def init(self, config) -> None:
        super().init(config)
        self.timeout = config.int_of("hostname_timeout_ms", 200, 30000) / 1000.0

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        previous = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            name = socket.gethostbyaddr(subject.ip)[0]
            if name and name != subject.ip:
                subject.set("hostname", name)
                return name
            return None
        except (socket.herror, socket.gaierror, OSError):
            return None
        finally:
            socket.setdefaulttimeout(previous)


@register
class CommentFetcher(Fetcher):
    """A free-text note you can attach to an address; persisted in config."""

    id = "comment"
    name = "Comment"
    description = "Your own note about this host."
    requires_alive = False
    order = 90
    width = 180

    def init(self, config) -> None:
        super().init(config)
        self.comments = dict(config.get("comments", {}) or {})

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        return self.comments.get(subject.ip) or None
