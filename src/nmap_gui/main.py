"""Application entry point."""
from __future__ import annotations

import argparse
import logging
import multiprocessing as mp
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox

# PyInstaller executes main.py as a top-level script. When that happens
# ``__package__`` is empty and the parent directory (project/src root) is not on
# ``sys.path``. Add it so the ``nmap_gui`` package can be imported normally.
if __package__ in (None, ""):  # pragma: no cover - script-only path adjustments
    package_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(package_dir.parent))

try:
    from .gui import MainWindow  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - fallback for direct script execution
    # When the module is executed as ``python main.py`` there is no package
    # context, so fall back to an absolute import to support that workflow.
    from nmap_gui.gui import MainWindow

try:
    from .infrastructure.config import ConfigurationError, get_settings
except ImportError:  # pragma: no cover - mirrors gui fallback for PyInstaller
    from nmap_gui.infrastructure.config import ConfigurationError, get_settings


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Nmap GUI discovery and rating tool")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging output",
    )
    parser.add_argument(
        "--mode",
        choices=("gui", "runner"),
        default="gui",
        help="Launch the GUI (default) or the privileged runner helper",
    )
    parser.add_argument(
        "--ipc-name",
        help="Named pipe endpoint passed to --mode runner",
    )
    parser.add_argument(
        "--ipc-token",
        help="Authentication token passed to --mode runner",
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

    if args.mode == "runner":
        return _run_privileged_mode(args)
    app = QApplication(sys.argv)
    try:
        from .gui.view.app_icon import load_app_icon
    except ImportError:  # pragma: no cover - mirrors main window fallback
        from nmap_gui.gui.view.app_icon import load_app_icon

    app_icon = load_app_icon()
    if not app_icon.isNull():
        app.setWindowIcon(app_icon)
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
    window = MainWindow(settings, app_icon=app_icon)
    window.show()
    return app.exec()


def _run_privileged_mode(args) -> int:
    if sys.platform != "win32":
        logging.error("Privileged runner mode is only available on Windows")
        return 2
    if not args.ipc_name or not args.ipc_token:
        logging.error("--ipc-name and --ipc-token are required for runner mode")
        return 2
    try:
        from .privileged_runner import run_privileged_runner
    except ImportError:  # pragma: no cover - shouldn't happen in packaged builds
        from nmap_gui.privileged_runner import run_privileged_runner
    return run_privileged_runner(args.ipc_name, args.ipc_token)


if __name__ == "__main__":  # pragma: no cover - CLI entry hand-off
    sys.exit(main())
