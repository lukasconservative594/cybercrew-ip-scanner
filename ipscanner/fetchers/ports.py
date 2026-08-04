"""Port scanning fetchers.

Only ``PortsFetcher`` does the network work; the service, banner and filtered
columns reuse its result through the subject scratchpad so that enabling all
four costs the same as enabling one.
"""

from __future__ import annotations

from typing import Optional

from ..core import portscan
from ..core.ranges import format_ports, parse_ports
from ..core.subject import HostState, ScanningSubject
from .base import Fetcher, register

SCAN_KEY = "port_scan"


@register
class PortsFetcher(Fetcher):
    id = "ports"
    name = "Open Ports"
    description = "TCP ports accepting connections."
    order = 40
    width = 180

    def init(self, config) -> None:
        super().init(config)
        try:
            self.ports = parse_ports(str(config.get("ports", "")))
        except Exception:
            self.ports = [21, 22, 23, 25, 80, 139, 443, 445, 3389]
        self.timeout = config.int_of("port_timeout_ms", 50, 60000) / 1000.0
        self.batch = config.int_of("port_batch", 1, 512)
        self.detect_filtered = config.bool_of("detect_filtered_ports")

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        if not self.ports:
            return None
        result = portscan.scan_ports(
            subject.ip,
            subject.family,
            self.ports,
            timeout=self.timeout,
            batch=self.batch,
            detect_filtered=self.detect_filtered,
            should_abort=lambda: subject.aborted,
        )
        subject.set(SCAN_KEY, result)
        subject.set("open_ports", result.open_ports)
        if result.open_ports:
            subject.promote(HostState.WITH_PORTS)
            return format_ports(result.open_ports)
        return None


@register
class FilteredPortsFetcher(Fetcher):
    """Ports that neither accepted nor refused - silently dropped.

    Enable ``detect_filtered_ports`` for this to have anything to show; a
    dropped packet is only distinguishable from a closed one by waiting for
    the full timeout, which is why it is off by default.
    """

    id = "filtered"
    name = "Filtered Ports"
    description = "Ports dropped without a reply (firewalled)."
    order = 41
    width = 160

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        result = subject.get(SCAN_KEY)
        if result is None or not result.filtered_ports:
            return None
        return format_ports(result.filtered_ports)


@register
class ServiceFetcher(Fetcher):
    """Well-known service names for the open ports."""

    id = "services"
    name = "Services"
    description = "Likely service behind each open port."
    order = 42
    width = 200

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        ports = subject.get("open_ports") or []
        if not ports:
            return None
        named = []
        for port in ports:
            service = portscan.service_name(port)
            named.append(f"{port}/{service}" if service else str(port))
        return ", ".join(named)


@register
class BannerFetcher(Fetcher):
    """Grabs a short service banner from each open port.

    This is the column that turns a port list into something actionable -
    versions here are what you feed into a CVE lookup.
    """

    id = "banner"
    name = "Banners"
    description = "Service banner / version string per open port."
    order = 43
    width = 320

    def init(self, config) -> None:
        super().init(config)
        self.enabled = config.bool_of("grab_banners")
        self.timeout = max(0.5, config.int_of("port_timeout_ms", 50, 60000) / 1000.0)
        self.max_ports = 12

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        if not self.enabled:
            return None
        ports = subject.get("open_ports") or []
        if not ports:
            return None
        parts = []
        for port in ports[: self.max_ports]:
            if subject.aborted:
                break
            banner = portscan.grab_banner(subject.ip, subject.family, port, self.timeout)
            if banner:
                parts.append(f"{port}: {banner}")
        return " | ".join(parts) if parts else None
