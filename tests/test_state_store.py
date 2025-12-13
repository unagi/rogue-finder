"""Tests for the state persistence helpers."""
from __future__ import annotations

import pickle
from pathlib import Path

from nmap_gui.state_store import CURRENT_STATE_VERSION, AppState, load_state, save_state
from nmap_gui.storage_warnings import consume_storage_warnings


def test_save_and_load_round_trip(tmp_path) -> None:
    path = tmp_path / "rogue-finder.state.bin"
    state = AppState(
        targets_text="10.0.0.1",
        icmp_enabled=False,
        ports_enabled=False,
        os_enabled=True,
        window_geometry=b"geometry",
    )

    assert save_state(state, path) is True
    loaded = load_state(path)

    assert loaded == state


def test_load_returns_none_when_version_mismatch(tmp_path) -> None:
    path = tmp_path / "state.bin"
    invalid = {"version": CURRENT_STATE_VERSION + 1, "targets_text": "old"}
    path.write_bytes(pickle.dumps(invalid))

    assert load_state(path) is None


def test_save_state_records_warning_on_failure(monkeypatch, tmp_path) -> None:
    failing_path = tmp_path / "broken.bin"
    consume_storage_warnings()
    original_open = Path.open

    def fake_open(self, *args, **kwargs):
        if self == failing_path:
            raise OSError("disk full")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fake_open)

    assert save_state(AppState(), failing_path) is False

    warnings = consume_storage_warnings()
    assert warnings
    assert warnings[0].scope == "state"
    assert warnings[0].path == failing_path
