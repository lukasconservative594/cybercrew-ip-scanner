"""Web server detection and TLS certificate fetchers."""

from __future__ import annotations

import http.client
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from ..core.portscan import _HTTP_PORTS, _TLS_PORTS
from ..core.subject import ScanningSubject
from .base import Fetcher, register

WEB_KEY = "web_probe"
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CHARSET_RE = re.compile(rb"charset=[\"']?([\w\-]+)", re.IGNORECASE)


@dataclass
class WebInfo:
    port: int = 0
    tls: bool = False
    status: str = ""
    server: str = ""
    title: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_expires: str = ""
    cert_expired: bool = False

    @property
    def scheme(self) -> str:
        return "https" if self.tls else "http"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{{host}}:{self.port}/"

    def __bool__(self) -> bool:
        return bool(self.status or self.server or self.title)


def _unverified_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe_web(ip: str, port: int, tls: bool, timeout: float = 3.0) -> Optional[WebInfo]:
    """One HTTP(S) GET, returning what the response reveals about the server."""
    info = WebInfo(port=port, tls=tls)
    conn = None
    try:
        if tls:
            conn = http.client.HTTPSConnection(
                ip, port, timeout=timeout, context=_unverified_context()
            )
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)

        conn.request("GET", "/", headers={
            "Host": ip,
            "User-Agent": "CyberCrewIPScanner/1.0",
            "Accept": "*/*",
            "Connection": "close",
        })
        response = conn.getresponse()
        info.status = f"{response.status} {response.reason}".strip()
        info.server = (response.getheader("Server") or "").strip()

        if tls and getattr(conn, "sock", None) is not None:
            _read_certificate(conn.sock, info)

        body = response.read(16384)
        info.title = _extract_title(body)
        return info if info else None
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return info if info else None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _read_certificate(sock, info: WebInfo) -> None:
    try:
        cert = sock.getpeercert()
    except (ValueError, OSError):
        return
    if not cert:
        return
    info.cert_subject = _name_of(cert.get("subject"))
    info.cert_issuer = _name_of(cert.get("issuer"))
    not_after = cert.get("notAfter")
    if not_after:
        info.cert_expires = str(not_after)
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            info.cert_expired = expiry.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
        except ValueError:
            pass


def _name_of(rdn_sequence) -> str:
    if not rdn_sequence:
        return ""
    for group in rdn_sequence:
        for key, value in group:
            if key == "commonName":
                return str(value)
    return ""


def _extract_title(body: bytes) -> str:
    match = _TITLE_RE.search(body or b"")
    if not match:
        return ""
    encoding = "utf-8"
    charset = _CHARSET_RE.search(body or b"")
    if charset:
        encoding = charset.group(1).decode("ascii", errors="ignore") or "utf-8"
    try:
        text = match.group(1).decode(encoding, errors="ignore")
    except LookupError:
        text = match.group(1).decode("utf-8", errors="ignore")
    return " ".join(text.split())[:120]


def _web_info(subject: ScanningSubject, config, timeout: float) -> Optional[WebInfo]:
    """Probe the most likely web port once, then cache for sibling fetchers."""
    if subject.has(WEB_KEY):
        return subject.get(WEB_KEY)

    configured = [int(p) for p in (config.get("web_detect_ports") or []) if str(p).isdigit()]
    open_ports = subject.get("open_ports")

    if open_ports is not None:
        # The port scan already ran: only try ports we know are listening.
        candidates = [p for p in open_ports if p in configured or p in _HTTP_PORTS or p in _TLS_PORTS]
    else:
        candidates = configured

    # Prefer TLS ports; a certificate tells you more than a plain banner.
    candidates.sort(key=lambda p: (p not in _TLS_PORTS, p))

    info = None
    for port in candidates[:4]:
        if subject.aborted:
            break
        tls = port in _TLS_PORTS
        found = probe_web(subject.ip, port, tls, timeout)
        if found:
            info = found
            break
        if tls:
            # Some services listen on a TLS port but speak plain HTTP.
            found = probe_web(subject.ip, port, False, timeout)
            if found:
                info = found
                break

    subject.set(WEB_KEY, info)
    return info


class _WebFetcher(Fetcher):
    order = 50

    def init(self, config) -> None:
        super().init(config)
        self.timeout = max(1.0, config.int_of("port_timeout_ms", 50, 60000) / 1000.0 * 2)


@register
class WebServerFetcher(_WebFetcher):
    id = "http"
    name = "Web Server"
    description = "Server header of any HTTP(S) service found."
    order = 50
    width = 200

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        info = _web_info(subject, self.config, self.timeout)
        if not info:
            return None
        label = info.server or info.status
        if not label:
            return None
        return f"{label} ({info.scheme}/{info.port})"


@register
class WebTitleFetcher(_WebFetcher):
    id = "http_title"
    name = "Page Title"
    description = "HTML <title> of the served page."
    order = 51
    width = 220

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        info = _web_info(subject, self.config, self.timeout)
        return info.title if info and info.title else None


@register
class TLSCertificateFetcher(_WebFetcher):
    """Certificate subject and expiry - expired certs are flagged inline."""

    id = "tls"
    name = "TLS Certificate"
    description = "Subject CN and expiry date of the presented certificate."
    order = 52
    width = 260

    def scan(self, subject: ScanningSubject) -> Optional[str]:
        info = _web_info(subject, self.config, self.timeout)
        if not info or not info.cert_subject:
            return None
        parts = [info.cert_subject]
        if info.cert_expires:
            parts.append("EXPIRED " + info.cert_expires if info.cert_expired
                         else "expires " + info.cert_expires)
        return " - ".join(parts)
