"""Low level, platform specific networking helpers.

Everything here degrades gracefully: if a privileged or platform specific
mechanism is unavailable we fall back to something that works everywhere, so
the scanner never hard-fails just because it is not running as root/admin.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Iterable, Optional

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# Hide console windows spawned by helper processes on Windows.
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


# --------------------------------------------------------------------------
# Windows ICMP / ARP via iphlpapi.dll (works without administrator rights)
# --------------------------------------------------------------------------

_iphlpapi = None
_ws2_32 = None

if IS_WINDOWS:  # pragma: no cover - platform specific
    import ctypes
    import ctypes.wintypes as wt

    try:
        _iphlpapi = ctypes.WinDLL("iphlpapi.dll")
        _ws2_32 = ctypes.WinDLL("ws2_32.dll")
    except OSError:
        _iphlpapi = None

if _iphlpapi is not None:  # pragma: no cover - platform specific
    import ctypes
    import ctypes.wintypes as wt

    class _IPOptionInformation(ctypes.Structure):
        _fields_ = [
            ("Ttl", ctypes.c_ubyte),
            ("Tos", ctypes.c_ubyte),
            ("Flags", ctypes.c_ubyte),
            ("OptionsSize", ctypes.c_ubyte),
            ("OptionsData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    class _IcmpEchoReply(ctypes.Structure):
        _fields_ = [
            ("Address", ctypes.c_uint32),
            ("Status", ctypes.c_ulong),
            ("RoundTripTime", ctypes.c_ulong),
            ("DataSize", ctypes.c_ushort),
            ("Reserved", ctypes.c_ushort),
            ("Data", ctypes.c_void_p),
            ("Options", _IPOptionInformation),
        ]

    class _SockAddrIn6(ctypes.Structure):
        _fields_ = [
            ("sin6_family", ctypes.c_short),
            ("sin6_port", ctypes.c_ushort),
            ("sin6_flowinfo", ctypes.c_ulong),
            ("sin6_addr", ctypes.c_ubyte * 16),
            ("sin6_scope_id", ctypes.c_ulong),
        ]

    class _Icmp6EchoReply(ctypes.Structure):
        _fields_ = [
            ("Address", _SockAddrIn6),
            ("Status", ctypes.c_ulong),
            ("RoundTripTime", ctypes.c_uint),
        ]

    _iphlpapi.IcmpCreateFile.restype = wt.HANDLE
    _iphlpapi.IcmpCreateFile.argtypes = []
    _iphlpapi.IcmpCloseHandle.restype = wt.BOOL
    _iphlpapi.IcmpCloseHandle.argtypes = [wt.HANDLE]
    _iphlpapi.IcmpSendEcho.restype = wt.DWORD
    _iphlpapi.IcmpSendEcho.argtypes = [
        wt.HANDLE,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_ushort,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wt.DWORD,
        wt.DWORD,
    ]
    _iphlpapi.SendARP.restype = wt.DWORD
    _iphlpapi.SendARP.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]

    try:
        _iphlpapi.Icmp6CreateFile.restype = wt.HANDLE
        _iphlpapi.Icmp6CreateFile.argtypes = []
        _iphlpapi.Icmp6SendEcho2.restype = wt.DWORD
        _HAVE_ICMP6 = True
    except AttributeError:
        _HAVE_ICMP6 = False
else:
    _HAVE_ICMP6 = False


@dataclass
class EchoReply:
    """Result of a single ICMP echo request."""

    success: bool
    rtt_ms: float = 0.0
    ttl: int = 0


def windows_icmp_echo(ip: str, timeout_ms: int, payload: bytes = b"CCRIPScanner") -> EchoReply:
    """Send one ICMP echo using the Windows helper API (no admin needed)."""
    if _iphlpapi is None:  # pragma: no cover
        return EchoReply(False)
    import ctypes

    handle = _iphlpapi.IcmpCreateFile()
    if handle == -1 or handle == 0:
        return EchoReply(False)
    try:
        dest = struct.unpack("<I", socket.inet_aton(ip))[0]
        reply_size = ctypes.sizeof(_IcmpEchoReply) + len(payload) + 64
        buf = ctypes.create_string_buffer(reply_size)
        req = ctypes.create_string_buffer(payload, len(payload))
        n = _iphlpapi.IcmpSendEcho(
            handle, dest, ctypes.byref(req), len(payload), None,
            ctypes.byref(buf), reply_size, max(1, int(timeout_ms)),
        )
        if n == 0:
            return EchoReply(False)
        reply = ctypes.cast(buf, ctypes.POINTER(_IcmpEchoReply)).contents
        if reply.Status != 0:  # IP_SUCCESS
            return EchoReply(False)
        return EchoReply(True, float(reply.RoundTripTime), int(reply.Options.Ttl))
    except Exception:
        return EchoReply(False)
    finally:
        _iphlpapi.IcmpCloseHandle(handle)


def windows_icmp6_echo(ip: str, timeout_ms: int, payload: bytes = b"CCRIPScanner") -> EchoReply:
    """Send one ICMPv6 echo using the Windows helper API."""
    if _iphlpapi is None or not _HAVE_ICMP6:  # pragma: no cover
        return EchoReply(False)
    import ctypes

    handle = _iphlpapi.Icmp6CreateFile()
    if handle in (0, -1):
        return EchoReply(False)
    try:
        src = _SockAddrIn6()
        src.sin6_family = socket.AF_INET6
        dst = _SockAddrIn6()
        dst.sin6_family = socket.AF_INET6
        packed = socket.inet_pton(socket.AF_INET6, ip)
        ctypes.memmove(dst.sin6_addr, packed, 16)

        reply_size = ctypes.sizeof(_Icmp6EchoReply) + len(payload) + 128
        buf = ctypes.create_string_buffer(reply_size)
        req = ctypes.create_string_buffer(payload, len(payload))
        n = _iphlpapi.Icmp6SendEcho2(
            handle, None, None, None,
            ctypes.byref(src), ctypes.byref(dst),
            ctypes.byref(req), len(payload), None,
            ctypes.byref(buf), reply_size, max(1, int(timeout_ms)),
        )
        if n == 0:
            return EchoReply(False)
        reply = ctypes.cast(buf, ctypes.POINTER(_Icmp6EchoReply)).contents
        if reply.Status != 0:
            return EchoReply(False)
        return EchoReply(True, float(reply.RoundTripTime), 0)
    except Exception:
        return EchoReply(False)
    finally:
        _iphlpapi.IcmpCloseHandle(handle)


def windows_send_arp(ip: str) -> Optional[str]:
    """Resolve a MAC address for a local-network IPv4 host via SendARP."""
    if _iphlpapi is None:  # pragma: no cover
        return None
    import ctypes

    try:
        dest = struct.unpack("<I", socket.inet_aton(ip))[0]
        mac = ctypes.create_string_buffer(8)
        length = ctypes.c_ulong(8)
        if _iphlpapi.SendARP(dest, 0, ctypes.byref(mac), ctypes.byref(length)) != 0:
            return None
        n = min(int(length.value), 8)
        if n < 6:
            return None
        return ":".join(f"{b:02X}" for b in mac.raw[:6])
    except Exception:
        return None


# --------------------------------------------------------------------------
# ARP table lookup (fallback for non-Windows or remote hosts)
# --------------------------------------------------------------------------

def arp_table_lookup(ip: str) -> Optional[str]:
    """Look up a MAC address in the OS ARP/neighbour cache."""
    try:
        if IS_LINUX:
            try:
                with open("/proc/net/arp", "r", encoding="ascii", errors="ignore") as fh:
                    next(fh, None)
                    for line in fh:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                            return parts[3].upper()
            except OSError:
                pass
            cmd = ["ip", "neigh", "show", ip]
        elif IS_WINDOWS:
            cmd = ["arp", "-a", ip]
        else:
            cmd = ["arp", "-n", ip]

        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=4,
            creationflags=_NO_WINDOW,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None

    return _extract_mac(out, ip)


def _extract_mac(text: str, ip: str) -> Optional[str]:
    for line in text.splitlines():
        if ip not in line:
            continue
        for token in line.replace("\t", " ").split():
            norm = token.replace("-", ":")
            parts = norm.split(":")
            if len(parts) == 6 and all(len(p) == 2 for p in parts):
                try:
                    int(norm.replace(":", ""), 16)
                except ValueError:
                    continue
                if norm.upper() == "00:00:00:00:00:00":
                    continue
                return norm.upper()
    return None


# --------------------------------------------------------------------------
# Local interface discovery
# --------------------------------------------------------------------------

@dataclass
class Interface:
    """A local network interface with an assigned address."""

    name: str
    address: str
    netmask: Optional[str] = None
    family: int = socket.AF_INET

    @property
    def network(self) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        if not self.netmask:
            return None
        try:
            return ipaddress.ip_network(f"{self.address}/{self.netmask}", strict=False)
        except ValueError:
            return None

    @property
    def prefix_len(self) -> Optional[int]:
        net = self.network
        return net.prefixlen if net else None


def local_interfaces(include_ipv6: bool = False) -> list[Interface]:
    """Enumerate local interfaces that carry a usable unicast address."""
    found: list[Interface] = []
    try:
        import psutil  # type: ignore

        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address and not a.address.startswith("127."):
                    found.append(Interface(name, a.address, a.netmask, socket.AF_INET))
                elif include_ipv6 and a.family == socket.AF_INET6 and a.address:
                    addr = a.address.split("%")[0]
                    if addr.startswith(("fe80", "::1")):
                        continue
                    found.append(Interface(name, addr, a.netmask, socket.AF_INET6))
    except Exception:
        pass

    if not found:
        ip = default_local_ip()
        if ip:
            found.append(Interface("default", ip, "255.255.255.0", socket.AF_INET))
    return found


def default_local_ip() -> Optional[str]:
    """Best guess at the address used to reach the outside world."""
    for probe, family in (("8.8.8.8", socket.AF_INET), ("2001:4860:4860::8888", socket.AF_INET6)):
        s = socket.socket(family, socket.SOCK_DGRAM)
        try:
            s.settimeout(0.4)
            s.connect((probe, 53))
            return s.getsockname()[0].split("%")[0]
        except OSError:
            continue
        finally:
            s.close()
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return None


def primary_interface() -> Optional[Interface]:
    """The interface holding the default outbound address, if identifiable."""
    ip = default_local_ip()
    if not ip:
        return None
    for iface in local_interfaces():
        if iface.address == ip:
            return iface
    return Interface("default", ip, "255.255.255.0", socket.AF_INET)


def local_addresses() -> set[str]:
    return {i.address for i in local_interfaces(include_ipv6=True)}


# --------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------

def family_of(address) -> int:
    return socket.AF_INET6 if getattr(address, "version", 4) == 6 else socket.AF_INET


def can_use_raw_sockets() -> bool:
    """Whether raw ICMP sockets are usable in this process."""
    if IS_WINDOWS:
        return False  # the helper API is strictly better here
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return True
    except (OSError, AttributeError):
        return False


def can_use_dgram_icmp() -> bool:
    """Linux/macOS unprivileged ICMP datagram sockets."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        s.close()
        return True
    except (OSError, AttributeError):
        return False
