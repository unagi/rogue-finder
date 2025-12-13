"""Tests for the state persistence helpers."""
from __future__ import annotations

import pickle
from pathlib import Path
from types import SimpleNamespace

import nmap_gui.state_store as state_store_module
from nmap_gui.state_store import (
    CURRENT_STATE_VERSION,
    AppState,
    load_state,
    save_state,
)
from nmap_gui.storage_warnings import consume_storage_warnings


def test_save_and_load_round_trip(tmp_path) -> None:
    path = tmp_path / "rogue-finder.state.bin"
    state = AppState(
        targets_text="198.51.100.1",
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


def test_load_state_returns_none_when_missing(tmp_path) -> None:
    path = tmp_path / "missing.bin"

    assert load_state(path) is None


def test_load_state_handles_pickle_errors(monkeypatch, tmp_path) -> None:
    path = tmp_path / "state.bin"
    path.write_bytes(b"invalid payload")
    original_open = Path.open

    def fake_open(self, *args, **kwargs):
        if self == path:
            raise pickle.UnpicklingError("corrupt")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fake_open)

    assert load_state(path) is None


def test_load_state_discards_uncoercible_payload(tmp_path) -> None:
    path = tmp_path / "state.bin"
    path.write_bytes(pickle.dumps(123))

    assert load_state(path) is None


def test_resolve_runtime_directory_for_frozen(monkeypatch, tmp_path) -> None:
    executable = tmp_path / "rogue-finder.exe"
    executable.write_text("")
    fake_sys = SimpleNamespace(frozen=True, executable=str(executable))
    monkeypatch.setattr(state_store_module, "sys", fake_sys)

    resolved = state_store_module._resolve_runtime_directory()

    assert resolved == executable.resolve().parent


def test_resolve_runtime_directory_prefers_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(state_store_module, "sys", SimpleNamespace(frozen=False))
    monkeypatch.setenv("ROGUE_FINDER_RUNTIME_DIR", str(tmp_path))

    resolved = state_store_module._resolve_runtime_directory()

    assert resolved == tmp_path.resolve()


def test_coerce_state_handles_dict_type_error(monkeypatch) -> None:
    class FailingAppState:
        def __init__(self, **kwargs):
            raise TypeError("bad data")

    monkeypatch.setattr(state_store_module, "AppState", FailingAppState)

    assert state_store_module._coerce_state({"targets_text": "value"}) is None
