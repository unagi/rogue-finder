"""Application state persistence helpers."""
from __future__ import annotations

import logging
import os
import pickle
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set

from .models import HostScanResult
from .storage_warnings import record_storage_warning


LOGGER = logging.getLogger(__name__)

STATE_FILENAME = "rogue-finder.state.bin"
CURRENT_STATE_VERSION = 2


@dataclass
class AppState:
    """Lightweight snapshot of GUI controls."""

    version: int = CURRENT_STATE_VERSION
    targets_text: str = ""
    icmp_enabled: bool = True
    ports_enabled: bool = True
    os_enabled: bool = True
    window_geometry: bytes | None = None
    results: List[HostScanResult] = field(default_factory=list)
    advanced_selected: Set[str] = field(default_factory=set)
    os_selected: Set[str] = field(default_factory=set)
    safety_selected: Set[str] = field(default_factory=set)


def load_state(path: Path | None = None) -> AppState | None:
    """Load the serialized state when it matches the current version."""

    state_path = _resolve_state_path(path)
    if not state_path.exists():
        return None
    try:
        with state_path.open("rb") as handle:
            payload = pickle.load(handle)
    except (OSError, pickle.PickleError, EOFError, AttributeError) as exc:
        LOGGER.debug("Failed to read state %s: %s", state_path, exc)
        return None
    state = _coerce_state(payload)
    if not state:
        return None
    if getattr(state, "version", None) != CURRENT_STATE_VERSION:
        LOGGER.info(
            "State version mismatch (found=%s expected=%s) – discarding",
            getattr(state, "version", None),
            CURRENT_STATE_VERSION,
        )
        return None
    return state


def save_state(state: AppState, path: Path | None = None) -> bool:
    """Persist ``state`` to disk, returning True on success."""

    state_path = _resolve_state_path(path)
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        with state_path.open("wb") as handle:
            pickle.dump(state, handle)
    except OSError as exc:
        LOGGER.warning("Failed to write state %s: %s", state_path, exc)
        record_storage_warning(scope="state", action="write", path=state_path, detail=str(exc))
        return False
    return True


def get_state_path(path: Path | None = None) -> Path:
    """Return the resolved state path (useful for tests)."""

    return _resolve_state_path(path)


def _resolve_state_path(path: Path | None = None) -> Path:
    if path is not None:
        return Path(path)
    return _resolve_runtime_directory() / STATE_FILENAME


def _resolve_runtime_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    if os.environ.get("ROGUE_FINDER_RUNTIME_DIR"):
        return Path(os.environ["ROGUE_FINDER_RUNTIME_DIR"]).expanduser().resolve()
    return Path.cwd()


def _coerce_state(payload: object) -> AppState | None:
    if isinstance(payload, AppState):
        return AppState(
            version=getattr(payload, "version", CURRENT_STATE_VERSION),
            targets_text=getattr(payload, "targets_text", ""),
            icmp_enabled=getattr(payload, "icmp_enabled", True),
            ports_enabled=getattr(payload, "ports_enabled", True),
            os_enabled=getattr(payload, "os_enabled", True),
            window_geometry=getattr(payload, "window_geometry", None),
            results=list(getattr(payload, "results", [])),
            advanced_selected=set(getattr(payload, "advanced_selected", set())),
            os_selected=set(getattr(payload, "os_selected", set())),
            safety_selected=set(getattr(payload, "safety_selected", set())),
        )
    if isinstance(payload, dict):
        data = {
            "version": payload.get("version", CURRENT_STATE_VERSION),
            "targets_text": payload.get("targets_text", ""),
            "icmp_enabled": payload.get("icmp_enabled", True),
            "ports_enabled": payload.get("ports_enabled", True),
            "os_enabled": payload.get("os_enabled", True),
            "window_geometry": payload.get("window_geometry"),
            "results": payload.get("results", []),
            "advanced_selected": set(payload.get("advanced_selected", [])),
            "os_selected": set(payload.get("os_selected", [])),
            "safety_selected": set(payload.get("safety_selected", [])),
        }
        try:
            return AppState(**data)
        except TypeError:
            return None
    return None
