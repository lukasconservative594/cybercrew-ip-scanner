#!/usr/bin/env python3
"""Build a portable CyberCrew IP Scanner binary for the current platform.

    python build.py              # build
    python build.py --clean      # remove build artefacts first
    python build.py --refresh    # also re-download the MAC vendor registry

The result is a single self-contained file in dist/ that needs no installer
and no Python on the target machine.
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
SPEC = ROOT / "cybercrew-ip-scanner.spec"

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"


def run(command: list[str], **kwargs) -> int:
    print(f"  $ {' '.join(command)}")
    return subprocess.run(command, cwd=ROOT, **kwargs).returncode


def ensure_pyinstaller() -> bool:
    try:
        import PyInstaller  # noqa: F401

        return True
    except ImportError:
        print("PyInstaller is missing; installing it now.")
        return run([sys.executable, "-m", "pip", "install", "pyinstaller"]) == 0


def platform_tag() -> str:
    system = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")
    machine = platform.machine().lower()
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64",
            "aarch64": "arm64"}.get(machine, machine)
    return f"{system}-{arch}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--clean", action="store_true", help="delete build/ and dist/ first")
    parser.add_argument("--refresh", action="store_true",
                        help="re-download the IEEE MAC vendor registry")
    parser.add_argument("--no-zip", action="store_true", help="skip the release archive")
    args = parser.parse_args()

    print(f"Building CyberCrew IP Scanner for {platform_tag()}\n")

    if args.clean:
        print("Cleaning previous artefacts")
        for folder in (BUILD, DIST):
            if folder.exists():
                shutil.rmtree(folder, ignore_errors=True)
                print(f"  removed {folder.name}/")

    registry = ROOT / "ipscanner" / "data" / "oui.csv.gz"
    if args.refresh or not registry.exists():
        print("\nRefreshing the MAC vendor registry")
        if run([sys.executable, str(ROOT / "tools" / "update_oui.py")]) != 0:
            if not registry.exists():
                print("error: no vendor registry available and the download failed.",
                      file=sys.stderr)
                return 1
            print("  warning: download failed, using the existing bundled copy")

    print("\nRendering the application icon")
    run([sys.executable, str(ROOT / "tools" / "make_icon.py")])

    print("\nRunning PyInstaller")
    if not ensure_pyinstaller():
        print("error: could not install PyInstaller", file=sys.stderr)
        return 1
    if run([sys.executable, "-m", "PyInstaller", str(SPEC), "--noconfirm",
            "--distpath", str(DIST), "--workpath", str(BUILD)]) != 0:
        print("error: the build failed", file=sys.stderr)
        return 1

    artefact = _find_artefact()
    if artefact is None:
        print("error: no binary was produced", file=sys.stderr)
        return 1

    size_mb = _size_of(artefact) / (1024 * 1024)
    print(f"\nBuilt {artefact.name}  ({size_mb:.1f} MB)")
    print(f"  {artefact}")

    if not args.no_zip:
        archive = _package(artefact)
        if archive:
            archive_mb = archive.stat().st_size / (1024 * 1024)
            print(f"\nPackaged {archive.name}  ({archive_mb:.1f} MB)")
            print(f"  {archive}")

    print("\nDone. The binary is portable - copy it anywhere and run it.")
    return 0


def _find_artefact() -> Path | None:
    if IS_MACOS:
        bundle = DIST / "CyberCrew IP Scanner.app"
        if bundle.exists():
            return bundle
    name = "CyberCrewIPScanner.exe" if IS_WINDOWS else "CyberCrewIPScanner"
    candidate = DIST / name
    return candidate if candidate.exists() else None


def _size_of(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def _package(artefact: Path) -> Path | None:
    """Zip the binary with the readme and licence for a release download."""
    archive = DIST / f"CyberCrewIPScanner-{platform_tag()}.zip"
    try:
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            if artefact.is_file():
                zf.write(artefact, artefact.name)
            else:
                for path in artefact.rglob("*"):
                    if path.is_file():
                        zf.write(path, str(path.relative_to(artefact.parent)))
            for extra in ("README.md", "LICENSE"):
                source = ROOT / extra
                if source.exists():
                    zf.write(source, extra)
            # Shipping this marker makes the binary keep its settings beside
            # itself, which is what you want on a USB stick.
            zf.writestr(
                "portable.txt",
                "Delete this file to store settings in your user profile "
                "instead of next to the executable.\n",
            )
        return archive
    except OSError as exc:
        print(f"  warning: could not create the archive: {exc}", file=sys.stderr)
        return None


if __name__ == "__main__":
    raise SystemExit(main())
