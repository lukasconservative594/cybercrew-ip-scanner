"""MAC address and vendor fetchers.

MAC resolution only works for hosts on a directly attached subnet - routers
rewrite the layer-2 header, so a MAC for a remote host simply does not exist
to be found. We check that first rather than burning a timeout on it.
"""

from __future__ import annotations

from typing import Optional

from ..core import net, oui
from ..core.pingers import is_local_subnet
from ..core.subject import ScanningSubject
from .base import Fetcher, register


@register
class MACFetcher(Fetcher):
    id = "mac"
    name = "MAC Address"
    description = "Layer-2 address (local subnet only)."
    order = 30
    width = 140

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        cached = subject.get("mac")
        if cached:
            return cached

        if subject.address.version != 4 or not is_local_subnet(subject.address):
            return None

        mac = None
        if net.IS_WINDOWS:
            mac = net.windows_send_arp(subject.ip)
        if not mac:
            mac = net.arp_table_lookup(subject.ip)
        if mac:
            subject.set("mac", mac)
        return mac


@register
class VendorFetcher(Fetcher):
    id = "vendor"
    name = "Vendor"
    description = "Hardware manufacturer derived from the MAC prefix."
    order = 31
    width = 160

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        mac = subject.get("mac")
        if not mac:
            return None
        return oui.lookup(mac)
