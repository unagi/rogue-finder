"""Model helper tests."""
from __future__ import annotations

from nmap_gui.models import sanitize_targets


def test_sanitize_targets_supports_various_separators() -> None:
    raw = "203.0.113.1,198.51.100.0/24; host.local\nexample.com\t"
    assert sanitize_targets(raw) == [
        "203.0.113.1",
        "198.51.100.0/24",
        "host.local",
        "example.com",
    ]


def test_sanitize_targets_handles_empty_input() -> None:
    assert sanitize_targets("") == []
