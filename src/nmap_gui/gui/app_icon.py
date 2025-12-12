"""Helpers for loading the application icon across platforms."""
from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from PySide6.QtGui import QIcon

ASSET_SUBPATH = Path("assets") / "icons"
PLATFORM_ICON = {
    "win32": "rogue-finder.ico",
    "cygwin": "rogue-finder.ico",
    "darwin": "rogue-finder.icns",
}
FALLBACK_ICONS = ("rogue-finder.ico", "icon_master.png")


def _asset_roots() -> list[Path]:
    roots: list[Path] = []
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        roots.append(Path(frozen_root))
    module_root = Path(__file__).resolve()
    for parent in module_root.parents:
        roots.append(parent)
    cwd = Path.cwd().resolve()
    if cwd not in roots:
        roots.append(cwd)
    return roots


def _candidate_paths(filename: str) -> Iterable[Path]:
    rel_path = ASSET_SUBPATH / filename
    seen: set[Path] = set()
    for root in _asset_roots():
        candidate = (root / rel_path).resolve()
        if candidate in seen:
            continue
        seen.add(candidate)
        yield candidate


@lru_cache(maxsize=1)
def load_app_icon() -> QIcon:
    """Return the best-fit QIcon for the current platform."""

    preferred = PLATFORM_ICON.get(sys.platform)
    search_order: list[str] = []
    if preferred:
        search_order.append(preferred)
    for candidate in FALLBACK_ICONS:
        if candidate not in search_order:
            search_order.append(candidate)
    for filename in search_order:
        for path in _candidate_paths(filename):
            if not path.exists():
                continue
            icon = QIcon(str(path))
            if not icon.isNull():
                return icon
    return QIcon()
