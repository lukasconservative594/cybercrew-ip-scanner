"""Saving scan results.

Every exporter takes the same (results, fetchers) pair so the file always
contains exactly the columns that were on screen.
"""

from __future__ import annotations

import csv
import html
import json
import os
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Sequence

from . import APP_NAME, APP_URL, __version__
from .core.subject import HostState, ScanResult


class ExportError(Exception):
    """Raised when results cannot be written."""


FORMATS: dict[str, str] = {
    "csv": "Comma separated values (*.csv)",
    "txt": "Plain text, aligned columns (*.txt)",
    "xml": "XML document (*.xml)",
    "json": "JSON document (*.json)",
    "lst": "IP:Port list (*.txt)",
    "html": "HTML report (*.html)",
}

_EXT_TO_FORMAT = {
    ".csv": "csv", ".txt": "txt", ".xml": "xml",
    ".json": "json", ".lst": "lst", ".html": "html", ".htm": "html",
}


def format_for(path: str | os.PathLike) -> str:
    return _EXT_TO_FORMAT.get(Path(path).suffix.lower(), "csv")


def export(
    results: Sequence[ScanResult],
    path: str | os.PathLike,
    fetchers: Sequence,
    fmt: str | None = None,
    not_available: str = "",
    not_scanned: str = "",
    feeder_info: str = "",
) -> int:
    """Write *results* to *path*. Returns the number of rows written."""
    fmt = (fmt or format_for(path)).lower()
    writer = _WRITERS.get(fmt)
    if writer is None:
        raise ExportError(f"Unknown export format: {fmt}")

    ctx = _Context(fetchers, not_available, not_scanned, feeder_info)
    try:
        return writer(list(results), Path(path), ctx)
    except OSError as exc:
        raise ExportError(str(exc)) from exc


class _Context:
    def __init__(self, fetchers, not_available, not_scanned, feeder_info):
        self.fetchers = list(fetchers)
        self.not_available = not_available
        self.not_scanned = not_scanned
        self.feeder_info = feeder_info
        self.headers = [f.name for f in self.fetchers]
        self.ids = [f.id for f in self.fetchers]

    def row(self, result: ScanResult) -> list[str]:
        return [
            result.display(fid, self.not_available, self.not_scanned)
            for fid in self.ids
        ]


def _write_csv(results, path: Path, ctx: _Context) -> int:
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Status"] + ctx.headers)
        for result in results:
            writer.writerow([result.state.label] + ctx.row(result))
    return len(results)


def _write_txt(results, path: Path, ctx: _Context) -> int:
    headers = ["Status"] + ctx.headers
    rows = [[r.state.label] + ctx.row(r) for r in results]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def line(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"{APP_NAME} {__version__}\n")
        if ctx.feeder_info:
            fh.write(f"Range: {ctx.feeder_info}\n")
        fh.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        fh.write(line(headers) + "\n")
        fh.write("-" * min(200, sum(widths) + 2 * len(widths)) + "\n")
        for row in rows:
            fh.write(line(row) + "\n")
    return len(results)


def _write_xml(results, path: Path, ctx: _Context) -> int:
    root = ET.Element("scan", {
        "tool": APP_NAME,
        "version": __version__,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "range": ctx.feeder_info,
        "hosts": str(len(results)),
    })
    for result in results:
        host = ET.SubElement(root, "host", {"ip": result.ip, "status": result.state.label})
        for fetcher_id, name in zip(ctx.ids, ctx.headers):
            field = ET.SubElement(host, "field", {"id": fetcher_id, "name": name})
            field.text = result.display(fetcher_id, ctx.not_available, ctx.not_scanned)
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return len(results)


def _write_json(results, path: Path, ctx: _Context) -> int:
    payload = {
        "tool": APP_NAME,
        "version": __version__,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "range": ctx.feeder_info,
        "columns": [{"id": i, "name": n} for i, n in zip(ctx.ids, ctx.headers)],
        "hosts": [
            {
                "ip": r.ip,
                "status": r.state.label,
                **{fid: r.value(fid) for fid in ctx.ids},
            }
            for r in results
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return len(results)


def _write_lst(results, path: Path, ctx: _Context) -> int:
    """One ``ip:port`` per line - the format other tools like to be fed."""
    written = 0
    with open(path, "w", encoding="utf-8") as fh:
        for result in results:
            ports = result.value("ports")
            if not ports:
                continue
            for port in _iter_ports(ports):
                fh.write(f"{result.ip}:{port}\n")
                written += 1
    return written


def _iter_ports(value) -> Iterable[int]:
    if isinstance(value, (list, tuple)):
        for item in value:
            try:
                yield int(item)
            except (TypeError, ValueError):
                continue
        return
    for chunk in str(value).replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            try:
                yield from range(int(lo), int(hi) + 1)
            except ValueError:
                continue
        else:
            try:
                yield int(chunk)
            except ValueError:
                continue


_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light dark; --bg:#ffffff; --fg:#1a1d21; --muted:#6b7280;
  --line:#e5e7eb; --head:#f6f7f9; --accent:#0b7285; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#14171a; --fg:#e6e8ea;
  --muted:#9aa3ad; --line:#2a2f35; --head:#1c2126; --accent:#4dd4c4; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:2rem 1.25rem; background:var(--bg); color:var(--fg);
  font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
.wrap {{ max-width:1400px; margin:0 auto; }}
h1 {{ font-size:1.4rem; margin:0 0 .25rem; }}
.meta {{ color:var(--muted); font-size:.85rem; margin-bottom:1.5rem; }}
.cards {{ display:flex; flex-wrap:wrap; gap:.75rem; margin-bottom:1.5rem; }}
.card {{ border:1px solid var(--line); border-radius:8px; padding:.6rem .9rem; min-width:120px; }}
.card b {{ display:block; font-size:1.5rem; font-weight:600; }}
.card span {{ color:var(--muted); font-size:.78rem; text-transform:uppercase;
  letter-spacing:.04em; }}
.scroll {{ overflow-x:auto; border:1px solid var(--line); border-radius:8px; }}
table {{ border-collapse:collapse; width:100%; font-size:13px; }}
th, td {{ text-align:left; padding:.45rem .7rem; border-bottom:1px solid var(--line);
  white-space:nowrap; vertical-align:top; }}
th {{ background:var(--head); position:sticky; top:0; font-weight:600; }}
tbody tr:hover {{ background:var(--head); }}
.dot {{ display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:.45rem; }}
.s-ports .dot {{ background:#2f9e44; }} .s-alive .dot {{ background:#1c7ed6; }}
.s-dead .dot {{ background:#e03131; }} .s-unknown .dot {{ background:#868e96; }}
footer {{ margin-top:1.5rem; color:var(--muted); font-size:.8rem; }}
a {{ color:var(--accent); }}
</style></head><body><div class="wrap">
<h1>{title}</h1>
<div class="meta">{subtitle}</div>
<div class="cards">{cards}</div>
<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>
{body}
</tbody></table></div>
<footer>Generated by <a href="{url}">{app}</a> {version} on {generated}.</footer>
</div></body></html>
"""


def _write_html(results, path: Path, ctx: _Context) -> int:
    alive = sum(1 for r in results if r.state >= HostState.ALIVE)
    with_ports = sum(1 for r in results if r.state >= HostState.WITH_PORTS)
    total_ports = sum(len(list(_iter_ports(r.value("ports")))) for r in results
                      if r.value("ports"))

    cards = "".join(
        f'<div class="card"><b>{value}</b><span>{label}</span></div>'
        for label, value in (
            ("Hosts listed", len(results)),
            ("Alive", alive),
            ("With open ports", with_ports),
            ("Open ports", total_ports),
        )
    )
    head = "<th>Status</th>" + "".join(f"<th>{html.escape(h)}</th>" for h in ctx.headers)

    rows = []
    for result in results:
        css = f"s-{result.state.name.lower().replace('with_ports', 'ports')}"
        cells = "".join(
            f"<td>{html.escape(cell)}</td>" for cell in ctx.row(result)
        )
        rows.append(
            f'<tr class="{css}"><td><span class="dot"></span>'
            f"{html.escape(result.state.label)}</td>{cells}</tr>"
        )

    subtitle = f"Range: {html.escape(ctx.feeder_info)}" if ctx.feeder_info else "Scan results"
    document = _HTML_TEMPLATE.format(
        title=f"{APP_NAME} report",
        subtitle=subtitle,
        cards=cards,
        head=head,
        body="\n".join(rows),
        app=APP_NAME,
        url=APP_URL,
        version=__version__,
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(document)
    return len(results)


_WRITERS = {
    "csv": _write_csv,
    "txt": _write_txt,
    "xml": _write_xml,
    "json": _write_json,
    "lst": _write_lst,
    "html": _write_html,
}
