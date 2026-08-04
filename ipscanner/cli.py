"""Headless command line interface.

Useful when you want the scanner inside a pipeline or on a box with no
desktop - the same engine, the same fetchers, the same export formats.
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from pathlib import Path
from typing import Sequence

from . import APP_NAME, __version__
from .core import pingers
from .core.config import Config
from .core.ranges import (
    FileFeeder, RandomFeeder, RangeError, RangeFeeder, format_ports, parse_ports,
)
from .core.scanner import ScanStats, Scanner
from .core.subject import HostState, ScanResult
from .exporters import FORMATS, ExportError, export
from . import fetchers as fetchers_pkg

_STATE_COLOUR = {
    HostState.WITH_PORTS: "\033[32m",
    HostState.ALIVE: "\033[36m",
    HostState.DEAD: "\033[31m",
    HostState.UNKNOWN: "\033[90m",
}
_RESET = "\033[0m"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybercrew-ip-scanner",
        description=f"{APP_NAME} {__version__} - fast IP and port scanner.",
        epilog=(
            "Examples:\n"
            "  cybercrew-ip-scanner 192.168.1.0/24\n"
            "  cybercrew-ip-scanner 10.0.0.1-10.0.0.50 -p 22,80,443 -o report.html\n"
            "  cybercrew-ip-scanner --file targets.txt --fetchers ip,ping,ports,banner\n"
            "  cybercrew-ip-scanner --local -p 1-1024 --all\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?",
                        help="range, CIDR or wildcard: 10.0.0.1-50, 10.0.0.0/24, 10.0.*.*")
    parser.add_argument("--file", "-F", help="read targets from a file, one per line")
    parser.add_argument("--local", "-L", action="store_true",
                        help="scan the subnet this machine is on")
    parser.add_argument("--random", type=int, metavar="N",
                        help="sample N random addresses from the target network")

    scan = parser.add_argument_group("scanning")
    scan.add_argument("--ports", "-p", help="ports to scan, e.g. 22,80,443,8000-8100")
    scan.add_argument("--threads", "-t", type=int, help="parallel workers (default 100)")
    scan.add_argument("--timeout", type=int, metavar="MS", help="ping timeout in ms")
    scan.add_argument("--port-timeout", type=int, metavar="MS", help="port timeout in ms")
    scan.add_argument("--ping-count", type=int, help="echo requests per host")
    scan.add_argument("--ping-method", choices=sorted(pingers.PINGERS),
                      help="liveness probe to use (default combined)")
    scan.add_argument("--all", "-a", action="store_true",
                      help="show dead hosts too, and run every fetcher on them")
    scan.add_argument("--open-only", action="store_true",
                      help="only show hosts with at least one open port")
    scan.add_argument("--filtered", action="store_true",
                      help="also report ports that were silently dropped")

    out = parser.add_argument_group("output")
    out.add_argument("--fetchers", "-f",
                     help="comma separated fetcher ids (see --list-fetchers)")
    out.add_argument("--output", "-o", help="write results to a file")
    out.add_argument("--format", choices=sorted(FORMATS),
                     help="output format (default: inferred from the file extension)")
    out.add_argument("--no-colour", "--no-color", dest="no_colour", action="store_true")
    out.add_argument("--quiet", "-q", action="store_true", help="suppress progress output")
    out.add_argument("--list-fetchers", action="store_true", help="list fetchers and exit")
    out.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_fetchers:
        _print_fetchers()
        return 0

    config = Config()
    _apply_overrides(config, args)

    try:
        feeder = _build_feeder(args, config)
    except RangeError as exc:
        parser.error(str(exc))
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if feeder is None:
        parser.print_help()
        return 2

    ids = _fetcher_ids(args, config)
    active = fetchers_pkg.create(ids)
    if not active:
        print("error: no valid fetchers selected", file=sys.stderr)
        return 2

    colour = _use_colour(args)
    results: list[ScanResult] = []
    lock = threading.Lock()
    widths = [max(len(f.name), 12) for f in active]

    if not args.quiet:
        print(f"{APP_NAME} {__version__}", file=sys.stderr)
        print(f"Scanning {feeder.info} ({len(feeder)} hosts, "
              f"{config.int_of('max_threads')} threads)\n", file=sys.stderr)
        header = "  ".join(f.name.ljust(widths[i]) for i, f in enumerate(active))
        print(header)
        print("-" * min(len(header), 200))

    def on_result(result: ScanResult) -> None:
        with lock:
            results.append(result)
            _print_row(result, active, widths, colour)

    def on_progress(stats: ScanStats) -> None:
        if args.quiet or not sys.stderr.isatty():
            return
        if stats.scanned % 16 and stats.scanned != stats.total:
            return
        sys.stderr.write(
            f"\r\033[K  {stats.percent}%  {stats.scanned}/{stats.total}  "
            f"{stats.alive} alive  {stats.rate:.0f}/s"
        )
        sys.stderr.flush()

    scanner = Scanner(feeder, active, config,
                      on_result=on_result, on_progress=on_progress)

    started = time.monotonic()
    try:
        stats = scanner.run()
    except KeyboardInterrupt:
        scanner.abort()
        scanner.join(5)
        stats = scanner.stats
        print("\nAborted.", file=sys.stderr)

    if not args.quiet and sys.stderr.isatty():
        sys.stderr.write("\r\033[K")

    if not args.quiet:
        elapsed = time.monotonic() - started
        print(f"\n{stats.summary()} ({elapsed:.1f}s wall clock)", file=sys.stderr)

    if args.output:
        try:
            written = export(
                results, args.output, active, args.format,
                not_available=str(config.get("not_available_text", "")),
                not_scanned=str(config.get("not_scanned_text", "")),
                feeder_info=feeder.info,
            )
            print(f"Wrote {written} rows to {args.output}", file=sys.stderr)
        except ExportError as exc:
            print(f"error: could not export: {exc}", file=sys.stderr)
            return 1

    return 0


def _apply_overrides(config: Config, args) -> None:
    if args.ports:
        config.set("ports", args.ports)
    if args.threads:
        config.set("max_threads", max(1, args.threads))
    if args.timeout:
        config.set("ping_timeout_ms", args.timeout)
    if args.port_timeout:
        config.set("port_timeout_ms", args.port_timeout)
    if args.ping_count:
        config.set("ping_count", args.ping_count)
    if args.ping_method:
        config.set("ping_method", args.ping_method)
    if args.filtered:
        config.set("detect_filtered_ports", True)
    if args.all:
        config.set("display", "all")
        config.set("scan_dead_hosts", True)
    elif args.open_only:
        config.set("display", "ports")
    else:
        config.set("display", "alive")


def _build_feeder(args, config):
    skip_broadcast = config.bool_of("skip_broadcast")

    if args.file:
        return FileFeeder(args.file, skip_broadcast)

    target = args.target
    if args.local and not target:
        from .core import net

        iface = net.primary_interface()
        if iface is None or iface.network is None:
            raise RangeError("Could not determine the local subnet")
        network = iface.network
        target = f"{network.network_address}/{network.prefixlen}"

    if not target:
        return None

    if args.random:
        from .core.ranges import netmask_to_prefix, parse_ip

        if "/" in target:
            base, _, mask = target.partition("/")
            return RandomFeeder(parse_ip(base), netmask_to_prefix(mask),
                                args.random, skip_broadcast)
        return RandomFeeder(parse_ip(target), 24, args.random, skip_broadcast)

    return RangeFeeder.from_text(target, skip_broadcast)


def _fetcher_ids(args, config) -> list[str]:
    if args.fetchers:
        return [f.strip() for f in args.fetchers.split(",") if f.strip()]
    ids = list(config.get("selected_fetchers") or fetchers_pkg.default_ids())
    if args.ports and "ports" not in ids:
        ids.append("ports")
    if args.filtered and "filtered" not in ids:
        ids.append("filtered")
    return ids


def _use_colour(args) -> bool:
    if args.no_colour or os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Enable ANSI processing on the Windows console.
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            return False
    return True


def _print_row(result: ScanResult, active, widths, colour: bool) -> None:
    cells = []
    for i, fetcher in enumerate(active):
        text = result.display(fetcher.id, "-", "")
        cells.append(text.ljust(widths[i]))
    line = "  ".join(cells).rstrip()
    if colour:
        line = _STATE_COLOUR.get(result.state, "") + line + _RESET
    print(line, flush=True)


def _print_fetchers() -> None:
    print(f"{APP_NAME} - available fetchers\n")
    for cls in fetchers_pkg.available():
        default = " (default)" if cls.id in fetchers_pkg.default_ids() else ""
        print(f"  {cls.id:<14} {cls.name}{default}")
        if cls.description:
            print(f"  {'':<14} {cls.description}")
    print("\nSelect with --fetchers ip,ping,ports,banner")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
