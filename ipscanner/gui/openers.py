"""Customisable "openers" - launch an external tool against a selected host.

A command is a template with ``${...}`` placeholders filled in from the
selected row, so one entry covers every host you ever select.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from typing import Any

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QDesktopServices

from ..core.subject import ScanResult

_PLACEHOLDER = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

DEFAULT_OPENERS: list[dict[str, Any]] = [
    {"name": "Open in browser", "command": "http://${ip}/", "url": True},
    {"name": "Open in browser (HTTPS)", "command": "https://${ip}/", "url": True},
    {"name": "Browse first open port", "command": "http://${ip}:${port}/", "url": True},
    {"name": "Open Windows share", "command": r"\\${ip}", "url": True},
    {"name": "SSH", "command": "ssh://${ip}", "url": True},
    {"name": "Remote Desktop", "command": "mstsc /v:${ip}", "url": False},
]


def default_openers() -> list[dict[str, Any]]:
    openers = [dict(entry) for entry in DEFAULT_OPENERS]
    if not sys.platform.startswith("win"):
        openers = [o for o in openers
                   if o["name"] not in ("Open Windows share", "Remote Desktop")]
        openers.append({"name": "Browse SMB share", "command": "smb://${ip}/", "url": True})
    return openers


def values_for(result: ScanResult) -> dict[str, str]:
    """Placeholder values available to a command template."""
    values: dict[str, str] = {
        "ip": result.ip,
        "state": result.state.label,
    }
    for key, raw in result.values.items():
        if raw is None:
            continue
        if isinstance(raw, (list, tuple)):
            values[key] = ",".join(str(v) for v in raw)
        else:
            values[key] = str(raw)

    values.setdefault("hostname", result.ip)

    ports = result.value("ports")
    first = _first_port(ports)
    values["port"] = str(first) if first else "80"
    values["ports"] = str(ports) if ports else ""
    return values


def _first_port(ports) -> int | None:
    if not ports:
        return None
    if isinstance(ports, (list, tuple)):
        try:
            return int(ports[0])
        except (TypeError, ValueError, IndexError):
            return None
    text = str(ports).split(",")[0].split("-")[0].strip()
    try:
        return int(text)
    except ValueError:
        return None


def substitute(template: str, result: ScanResult) -> str:
    values = values_for(result)
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(1), ""), template or "")


def launch(opener: dict[str, Any], result: ScanResult) -> tuple[bool, str]:
    """Run one opener against one host. Returns (ok, message)."""
    command = substitute(str(opener.get("command", "")), result).strip()
    if not command:
        return False, "This opener has an empty command."

    if opener.get("url"):
        if command.startswith("\\\\"):
            # A UNC path is not a URL; hand it to the shell instead.
            try:
                os.startfile(command)  # type: ignore[attr-defined]
                return True, command
            except (OSError, AttributeError) as exc:
                return False, str(exc)
        if QDesktopServices.openUrl(QUrl(command)):
            return True, command
        return False, f"The system could not open {command}"

    try:
        if sys.platform.startswith("win"):
            subprocess.Popen(command, shell=True,
                             creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:
            subprocess.Popen(shlex.split(command))
        return True, command
    except (OSError, ValueError) as exc:
        return False, str(exc)
