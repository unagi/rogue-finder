"""Shared helpers for tracking storage-layer warnings."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StorageWarning:
    """Represents a recoverable storage failure that should reach the GUI."""

    scope: str
    action: str
    path: Path
    detail: str


_WARNINGS: list[StorageWarning] = []


def record_storage_warning(scope: str, action: str, path: Path, detail: str) -> None:
    """Add a warning describing a recoverable persistence failure."""

    _WARNINGS.append(StorageWarning(scope=scope, action=action, path=path, detail=detail))


def consume_storage_warnings() -> list[StorageWarning]:
    """Return and clear any pending storage warnings."""

    warnings = list(_WARNINGS)
    _WARNINGS.clear()
    return warnings
