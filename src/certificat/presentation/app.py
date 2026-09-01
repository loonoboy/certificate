"""Desktop application entrypoint."""

from __future__ import annotations

import sys
from typing import Sequence, cast

from PySide6.QtWidgets import QApplication

from .._version import __version__
from .main_window import MainWindow


def main(argv: Sequence[str] | None = None) -> int:
    existing = QApplication.instance()
    if existing is None:
        application = QApplication(list(argv) if argv is not None else sys.argv)
    else:
        application = cast(QApplication, existing)
    application.setApplicationName("Certificat")
    application.setApplicationVersion(__version__)
    application.setOrganizationName("Certificat")

    window = MainWindow()
    window.show()
    return application.exec()
