# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build definition.

Produces a single self-contained executable per platform. Build it with:

    python build.py

or directly:

    pyinstaller cybercrew-ip-scanner.spec --noconfirm
"""

import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve()
IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"

# The gzipped IEEE registry must travel with the binary so vendor lookup
# works offline on a machine that has never run the updater.
datas = [(str(ROOT / "ipscanner" / "data" / "oui.csv.gz"), "ipscanner/data")]

icon = None
if IS_WINDOWS and (ROOT / "assets" / "icon.ico").exists():
    icon = str(ROOT / "assets" / "icon.ico")
elif IS_MACOS and (ROOT / "assets" / "icon.icns").exists():
    icon = str(ROOT / "assets" / "icon.icns")

# Qt pulls in a lot we never touch. Dropping it keeps the download small.
excludes = [
    "PyQt6.QtWebEngineCore", "PyQt6.QtWebEngineWidgets", "PyQt6.QtWebEngine",
    "PyQt6.QtQml", "PyQt6.QtQuick", "PyQt6.QtQuick3D", "PyQt6.QtMultimedia",
    "PyQt6.QtMultimediaWidgets", "PyQt6.QtBluetooth", "PyQt6.QtNfc",
    "PyQt6.QtPositioning", "PyQt6.QtSerialPort", "PyQt6.QtSql", "PyQt6.QtTest",
    "PyQt6.QtDesigner", "PyQt6.QtHelp", "PyQt6.QtOpenGL", "PyQt6.QtCharts",
    "PyQt6.Qt3DCore", "PyQt6.QtDataVisualization", "PyQt6.QtPdf",
    "tkinter", "unittest", "pydoc_data", "test",
    "numpy", "pandas", "matplotlib", "scipy", "PIL",
]

a = Analysis(
    ["main.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=["psutil"],
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="CyberCrewIPScanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    # Windowed on Windows and macOS: double-clicking must not flash a console.
    # main.py reattaches to the parent console when given CLI arguments.
    console=not (IS_WINDOWS or IS_MACOS),
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon,
)

if IS_MACOS:
    app = BUNDLE(
        exe,
        name="CyberCrew IP Scanner.app",
        icon=icon,
        bundle_identifier="io.cybercrew.ipscanner",
        info_plist={
            "CFBundleName": "CyberCrew IP Scanner",
            "CFBundleDisplayName": "CyberCrew IP Scanner",
            "CFBundleShortVersionString": "1.0.0",
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
        },
    )
