"""Application bootstrap entry point for ThreatDesk.

Initializes:
- High-DPI attributes
- QApplication
- SQLite Database & seed migration
- MainWindow UI
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure package root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from app.storage.database import Database
from app.ui.main_window import MainWindow


def main() -> None:
    # High-DPI scaling configuration & Windows taskbar AppID
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "ChronoTrace.Workstation.App.1.0"
            )
        except OSError:
            pass

    app = QApplication(sys.argv)
    app.setApplicationName("ChronoTrace")
    app.setOrganizationName("SOC Defensive Workstation")

    icon_path = BASE_DIR / "app" / "assets" / "icon.ico"
    if not icon_path.exists():
        icon_path = BASE_DIR / "app" / "assets" / "logo.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # Initialize local SQLite DB & verify schema
    db = Database()

    # Launch GUI
    window = MainWindow(db)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
