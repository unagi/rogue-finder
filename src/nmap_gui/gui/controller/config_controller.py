"""Controller that mediates configuration I/O for the GUI."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ...infrastructure import config as config_module
from ...infrastructure.config import AppSettings


class ConfigController:
    """Wraps infrastructure config helpers for GUI-facing flows."""

    def __init__(self) -> None:
        self._config = config_module

    def resolve_path(self, path: Path | str | None) -> Path:
        return self._config.config_file_path(path)

    def load_settings(self, path: Path) -> AppSettings:
        return self._config.load_settings(path)

    def merge_with_defaults(self, data: dict[str, Any] | None) -> dict[str, Any]:
        return self._config.merge_with_defaults(data)

    def write_settings(self, data: dict[str, Any], path: Path) -> bool:
        return self._config.write_settings(data, path)

    def reset_cache(self) -> None:
        self._config.reset_settings_cache()

    def current_settings(self) -> AppSettings:
        return self._config.get_settings()
