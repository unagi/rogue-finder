"""Application entry point."""
from __future__ import annotations

import argparse
import logging
import multiprocessing as mp
import sys

from PySide6.QtWidgets import QApplication
from PySide6.QtWidgets import QMessageBox

try:
    from .gui import MainWindow  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - fallback for direct script execution
    # When the module is executed as ``python main.py`` there is no package
    # context, so fall back to an absolute import to support that workflow.
    from nmap_gui.gui import MainWindow

from .config import ConfigurationError, get_settings


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Nmap GUI discovery and rating tool")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    mp.freeze_support()
    app = QApplication(sys.argv)
    try:
        settings = get_settings()
    except ConfigurationError as exc:
        logging.exception("Failed to load configuration")
        QMessageBox.critical(
            None,
            "Configuration Error",
            f"Failed to load configuration file.\n{exc}\n"
            "Delete or fix rogue-finder.config.yaml and retry.",
        )
        return 1
    window = MainWindow(settings)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
