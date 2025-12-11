"""Utility helpers used across the GUI application."""
from __future__ import annotations

import re


_FILENAME_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


def slugify_filename_component(value: str, fallback: str = "report") -> str:
    """Return a filesystem-friendly fragment derived from user-visible text.

    The value is restricted to ASCII characters that play nicely across
    platforms, collapsing runs of unsupported characters into underscores and
    trimming leading/trailing separators. When the resulting string becomes
    empty, the fallback token is returned instead.
    """

    stripped = value.strip()
    sanitized = _FILENAME_PATTERN.sub("_", stripped)
    sanitized = sanitized.strip("._-")
    if not sanitized:
        sanitized = fallback
    return sanitized[:80]
