#!/usr/bin/env python3
"""
Scam Advisor - Website Trust Analyzer
Main entry point for the application
"""

import sys
import os

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt


# Enable High DPI Scaling (Clear UI)
QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)


# Add project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


from gui.main_window import MainWindow
from gui.theme_manager import ThemeManager
from config.settings import load_settings


def main():
    """Main application entry point"""

    # Create Application
    app = QApplication(sys.argv)

    # Global UI Style
    app.setStyleSheet("""
    /* Input Fields */
    QLineEdit {
        background-color: #ffffff;
        color: #000000;
        font-size: 15px;
        padding: 6px;
        border-radius: 5px;
        border: 1px solid #888;
    }

    QLineEdit:focus {
        border: 2px solid #2196f3;
    }

    /* Output Area */
    QTextEdit {
        background-color: #121212;
        color: #ffffff;
        font-size: 15px;
        border: 1px solid #333;
        padding: 8px;
    }

    /* Buttons */
    QPushButton {
        background-color: #2196f3;
        color: white;
        font-size: 14px;
        padding: 6px 12px;
        border-radius: 5px;
    }

    QPushButton:hover {
        background-color: #1976d2;
    }

    QListWidget {
        background-color: #1e1e1e;
        color: white;
        font-size: 13px;
    }
    """)

    # App Info
    app.setApplicationName("Scam Advisor")
    app.setApplicationVersion("1.0.0")

    # Load settings
    settings = load_settings()

    # Apply Theme
    theme_manager = ThemeManager()
    theme_manager.apply_theme(settings.get("theme", "dark"))

    # Create Main Window
    main_window = MainWindow(settings)

    # Open Maximized
    main_window.showMaximized()

    # Run App
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
