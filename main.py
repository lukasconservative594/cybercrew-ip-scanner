#!/usr/bin/env python3
"""CyberCrew IP Scanner launcher.

No arguments opens the window; any arguments run the command line scanner.

    python main.py                       # GUI
    python main.py 192.168.1.0/24        # CLI
    python main.py --help                # CLI options
"""

from __future__ import annotations

import multiprocessing
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def _attach_parent_console() -> None:
    """Let the packaged GUI binary also print to the terminal that launched it.

    The Windows build is windowed so double-clicking it does not flash a
    console. That normally means command line output goes nowhere, so when we
    are given arguments we reattach to the calling console and rebind the
    standard streams to it.
    """
    if not sys.platform.startswith("win") or not getattr(sys, "frozen", False):
        return
    try:
        import ctypes

        ATTACH_PARENT_PROCESS = -1
        if not ctypes.windll.kernel32.AttachConsole(ATTACH_PARENT_PROCESS):
            return
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
        sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
    except (OSError, AttributeError, ImportError):
        pass


def main() -> int:
    args = sys.argv[1:]

    if args:
        _attach_parent_console()

    if args and args[0] in ("--gui", "-g"):
        from ipscanner.app import run

        return run([sys.argv[0]])

    if args:
        from ipscanner.cli import main as cli_main

        return cli_main(args)

    from ipscanner.app import run

    return run()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
