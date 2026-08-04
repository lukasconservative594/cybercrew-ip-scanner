"""Fast TCP port scanning.

Rather than connecting to one port at a time, a whole batch of non-blocking
connects is fired off at once and a selector waits on all of them together.
The cost of scanning 128 ports is therefore roughly the cost of scanning one,
which is what makes a full sweep practical.
"""

from __future__ import annotations

import errno
import selectors
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Sequence

from . import net

_IN_PROGRESS = {
    errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN, errno.EALREADY,
    10035, 10036, 10022,
}

# select() on Windows caps out at FD_SETSIZE (512) descriptors per call.
_MAX_BATCH = 400 if net.IS_WINDOWS else 512


@dataclass
class PortScanResult:
    open_ports: list[int] = field(default_factory=list)
    filtered_ports: list[int] = field(default_factory=list)
    closed_count: int = 0
    banners: dict[int, str] = field(default_factory=dict)

    @property
    def has_open(self) -> bool:
        return bool(self.open_ports)


def scan_ports(
    ip: str,
    family: int,
    ports: Sequence[int],
    timeout: float = 1.2,
    batch: int = 128,
    detect_filtered: bool = False,
    should_abort: Optional[Callable[[], bool]] = None,
) -> PortScanResult:
    """Connect-scan *ports* on *ip*, returning open (and optionally filtered) ones."""
    result = PortScanResult()
    if not ports:
        return result

    batch = max(1, min(int(batch), _MAX_BATCH))
    timeout = max(0.05, float(timeout))

    for chunk in _chunks(list(ports), batch):
        if should_abort and should_abort():
            break
        _scan_chunk(ip, family, chunk, timeout, detect_filtered, result, should_abort)

    result.open_ports.sort()
    result.filtered_ports.sort()
    return result


def _scan_chunk(ip, family, chunk, timeout, detect_filtered, result, should_abort):
    selector = selectors.DefaultSelector()
    pending: dict[socket.socket, int] = {}
    try:
        for port in chunk:
            sock = socket.socket(family, socket.SOCK_STREAM)
            try:
                sock.setblocking(False)
                code = sock.connect_ex((ip, port))
            except OSError:
                sock.close()
                result.closed_count += 1
                continue

            if code == 0:
                result.open_ports.append(port)
                sock.close()
                continue
            if code in _IN_PROGRESS:
                try:
                    selector.register(sock, selectors.EVENT_WRITE, port)
                    pending[sock] = port
                except (ValueError, OSError):
                    sock.close()
            else:
                result.closed_count += 1
                sock.close()

        deadline = time.monotonic() + timeout
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if should_abort and should_abort():
                break
            for key, _events in selector.select(min(0.25, remaining)):
                sock = key.fileobj
                port = key.data
                try:
                    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                except OSError:
                    err = errno.ECONNREFUSED
                if err == 0:
                    result.open_ports.append(port)
                else:
                    result.closed_count += 1
                selector.unregister(sock)
                pending.pop(sock, None)
                sock.close()
    finally:
        # Anything still pending never answered: dropped by a firewall.
        for sock, port in pending.items():
            if detect_filtered:
                result.filtered_ports.append(port)
            try:
                selector.unregister(sock)
            except (KeyError, ValueError, OSError):
                pass
            sock.close()
        selector.close()


def _chunks(items: list, size: int) -> Iterable[list]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


# --------------------------------------------------------------------------
# Banner grabbing / service identification
# --------------------------------------------------------------------------

_HTTP_PORTS = {80, 81, 591, 2080, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090}
_TLS_PORTS = {443, 465, 636, 993, 995, 1443, 4443, 8443, 9443, 10443}

#: Binary protocols that will never answer a HEAD request - asking costs a
#: full timeout and tells us nothing, so we skip straight past them.
_NEVER_HTTP = {
    135, 137, 138, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986,
    6379, 11211, 27017, 27018, 2049, 623, 161, 500, 1723, 9042, 50000,
}

WELL_KNOWN = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 79: "finger", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 587: "submission", 623: "ipmi",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 2181: "zookeeper",
    2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 4444: "metasploit", 5060: "sip", 5432: "postgres",
    5555: "adb", 5601: "kibana", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls",
    6379: "redis", 6443: "kubernetes", 7001: "weblogic", 8000: "http-alt",
    8009: "ajp13", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8500: "consul", 9000: "http-alt", 9042: "cassandra", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    27018: "mongodb", 50000: "db2",
}


def service_name(port: int) -> str:
    return WELL_KNOWN.get(port, "")


def grab_banner(ip: str, family: int, port: int, timeout: float = 1.5) -> str:
    """Best-effort service banner for an already-known-open port."""
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if port in _TLS_PORTS:
            return _tls_banner(sock, ip, port, timeout)

        # Chatty protocols greet first; give them a short moment.
        sock.settimeout(min(timeout, 0.7))
        try:
            data = sock.recv(512)
            if data:
                return _clean(data)
        except (socket.timeout, TimeoutError, OSError):
            pass

        # Only speak HTTP where it might actually be listening. Probing SMB or
        # RDP with a HEAD request just burns a full timeout for nothing.
        if port in _HTTP_PORTS or (port > 1024 and port not in _NEVER_HTTP):
            try:
                sock.sendall(
                    b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n"
                    b"User-Agent: CyberCrewIPScanner\r\n\r\n"
                )
                data = sock.recv(1024)
                if data:
                    return _http_summary(data)
            except OSError:
                pass
        return ""
    except OSError:
        return ""
    finally:
        if sock is not None:
            sock.close()


def _tls_banner(sock: socket.socket, ip: str, port: int, timeout: float) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(sock, server_hostname=ip) as tls:
            tls.settimeout(timeout)
            parts = []
            version = tls.version()
            if version:
                parts.append(version)
            cert = tls.getpeercert()
            subject_cn = _cert_cn(cert)
            if subject_cn:
                parts.append(f"CN={subject_cn}")
            try:
                tls.sendall(
                    b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n"
                    b"User-Agent: CyberCrewIPScanner\r\n\r\n"
                )
                data = tls.recv(1024)
                summary = _http_summary(data)
                if summary:
                    parts.append(summary)
            except OSError:
                pass
            return " | ".join(p for p in parts if p)
    except (ssl.SSLError, OSError):
        return ""


def _cert_cn(cert) -> str:
    if not cert:
        return ""
    for field_group in cert.get("subject", ()):  # type: ignore[union-attr]
        for key, value in field_group:
            if key == "commonName":
                return str(value)
    return ""


def _http_summary(data: bytes) -> str:
    text = data.decode("latin-1", errors="ignore")
    lines = text.split("\r\n")
    status = lines[0].strip() if lines else ""
    server = ""
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    if server and status:
        return f"{status} ({server})"
    return server or status


def _clean(data: bytes) -> str:
    text = data.decode("latin-1", errors="ignore")
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch for ch in text if ch.isprintable())
    return " ".join(text.split())[:120]
