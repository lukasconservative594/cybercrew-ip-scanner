"""GUI entry point."""

from __future__ import annotations

import sys
from typing import Sequence

from . import APP_ID, APP_NAME, __version__


def run(argv: Sequence[str] | None = None) -> int:
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print(
            f"{APP_NAME} needs PyQt6 for its window.\n"
            "Install it with:  pip install PyQt6\n"
            "Or run the scanner headless:  python -m ipscanner.cli --help",
            file=sys.stderr,
        )
        return 1

    from .core.config import Config
    from .gui.main_window import MainWindow, app_icon

    QApplication.setApplicationName(APP_NAME)
    QApplication.setApplicationVersion(__version__)
    QApplication.setOrganizationName("CyberCrew")
    QApplication.setDesktopFileName(APP_ID)

    app = QApplication(list(argv) if argv is not None else sys.argv)
    app.setWindowIcon(app_icon())

    if sys.platform.startswith("win"):
        # Without this Windows groups the taskbar entry under python.exe.
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
        except Exception:
            pass

    config = Config()
    window = MainWindow(config)
    window.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())
