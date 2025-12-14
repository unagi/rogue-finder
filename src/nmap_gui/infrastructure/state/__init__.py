"""State persistence primitives for Rogue Finder."""
from __future__ import annotations

from .storage_warnings import (
    StorageWarning,
    consume_storage_warnings,
    record_storage_warning,
)
from .store import (
    CURRENT_STATE_VERSION,
    AppState,
    get_state_path,
    load_state,
    save_state,
)

__all__ = [
    "CURRENT_STATE_VERSION",
    "AppState",
    "StorageWarning",
    "consume_storage_warnings",
    "get_state_path",
    "load_state",
    "record_storage_warning",
    "save_state",
]
