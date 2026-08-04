#!/usr/bin/env python3
"""Refresh the bundled MAC vendor database.

Downloads the IEEE MA-L registry, strips it to ``prefix,vendor`` pairs and
writes a gzipped copy into the package so vendor lookup works offline in a
freshly built binary. Run this before cutting a release.

    python tools/update_oui.py
"""

from __future__ import annotations

import csv
import gzip
import io
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TARGET = ROOT / "ipscanner" / "data" / "oui.csv.gz"
SOURCES = [
    "https://standards-oui.ieee.org/oui/oui.csv",
    "https://standards-oui.ieee.org/cid/cid.csv",
    "https://standards-oui.ieee.org/iab/iab.csv",
    "https://standards-oui.ieee.org/oui28/mam.csv",
    "https://standards-oui.ieee.org/oui36/oui36.csv",
]


def fetch(url: str) -> str | None:
    print(f"  fetching {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "CyberCrewIPScanner/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read().decode("utf-8", errors="ignore")
    except Exception as exc:  # noqa: BLE001 - a missing source is not fatal
        print(f"    skipped: {exc}")
        return None


def parse(text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 3:
            continue
        assignment = "".join(c for c in row[1].upper() if c in "0123456789ABCDEF")
        vendor = row[2].strip().strip('"')
        if len(assignment) >= 6 and vendor and vendor.lower() != "organization name":
            rows.append((assignment[:6], vendor))
    return rows


def main() -> int:
    print("Building bundled MAC vendor database")
    merged: dict[str, str] = {}
    for url in SOURCES:
        text = fetch(url)
        if not text:
            continue
        pairs = parse(text)
        print(f"    {len(pairs)} prefixes")
        for prefix, vendor in pairs:
            merged.setdefault(prefix, vendor)

    if len(merged) < 1000:
        print("error: too few prefixes collected, refusing to overwrite", file=sys.stderr)
        return 1

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    for prefix in sorted(merged):
        writer.writerow([prefix, merged[prefix]])
    payload = buffer.getvalue().encode("utf-8")

    with gzip.open(TARGET, "wb", compresslevel=9) as fh:
        fh.write(payload)

    size_kb = TARGET.stat().st_size / 1024
    print(f"\nWrote {TARGET.relative_to(ROOT)}")
    print(f"  {len(merged)} vendor prefixes, {size_kb:.0f} KB compressed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
