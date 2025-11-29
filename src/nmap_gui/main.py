"""Application entry point."""
from __future__ import annotations

import argparse
import logging
import multiprocessing as mp
import sys

from PySide6.QtWidgets import QApplication

from .gui import MainWindow


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
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
