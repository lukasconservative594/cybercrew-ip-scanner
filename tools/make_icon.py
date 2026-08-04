#!/usr/bin/env python3
"""Render the application icon to assets/ for the packaged binaries.

The icon is drawn in code (see ipscanner/gui/main_window.py) so there is no
binary asset in version control; this script materialises it into the .ico
and .png files PyInstaller wants at build time.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ASSETS = ROOT / "assets"


def main() -> int:
    try:
        from PyQt6.QtGui import QPixmap
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print("PyQt6 is required to render the icon", file=sys.stderr)
        return 1

    from ipscanner.gui.main_window import app_icon

    _app = QApplication([])  # a QGuiApplication must exist before QPixmap
    ASSETS.mkdir(parents=True, exist_ok=True)
    icon = app_icon()

    sizes = [16, 32, 48, 64, 128, 256]
    pixmaps: list[QPixmap] = []
    for size in sizes:
        pixmap = icon.pixmap(size, size)
        pixmaps.append(pixmap)
        if size == 256:
            target = ASSETS / "icon.png"
            pixmap.save(str(target), "PNG")
            print(f"  wrote {target.relative_to(ROOT)}")

    ico = ASSETS / "icon.ico"
    if _write_ico(ico, pixmaps, sizes):
        print(f"  wrote {ico.relative_to(ROOT)}")
    else:
        print("  warning: could not write icon.ico; the exe will use the default icon",
              file=sys.stderr)

    icns = ASSETS / "icon.icns"
    largest = icon.pixmap(512, 512)
    if largest.save(str(ASSETS / "icon-512.png"), "PNG"):
        print(f"  wrote {(ASSETS / 'icon-512.png').relative_to(ROOT)}")
    if sys.platform == "darwin":
        _write_icns(icns)
    return 0


def _write_ico(path: Path, pixmaps, sizes) -> bool:
    """Prefer Pillow (real multi-resolution .ico); fall back to Qt."""
    try:
        from PIL import Image  # type: ignore

        png = ASSETS / "icon.png"
        if png.exists():
            Image.open(png).save(path, format="ICO",
                                 sizes=[(s, s) for s in sizes])
            return True
    except Exception:
        pass
    try:
        return bool(pixmaps[-1].save(str(path), "ICO"))
    except Exception:
        return False


def _write_icns(path: Path) -> None:  # pragma: no cover - macOS only
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "icon.iconset"
        iconset.mkdir()
        source = ASSETS / "icon-512.png"
        for size in (16, 32, 64, 128, 256, 512):
            subprocess.run(
                ["sips", "-z", str(size), str(size), str(source),
                 "--out", str(iconset / f"icon_{size}x{size}.png")],
                check=False, capture_output=True,
            )
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(path)],
                       check=False, capture_output=True)
        if path.exists():
            print(f"  wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    raise SystemExit(main())
