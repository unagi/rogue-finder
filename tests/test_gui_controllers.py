from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from nmap_gui.gui.controller import privileges, result_store as result_store_mod, state_controller as state_controller_mod
from nmap_gui.models import ErrorRecord, HostScanResult, SafeScanReport, ScanMode
from nmap_gui.state_store import AppState
from nmap_gui.storage_warnings import StorageWarning


def _make_result(target: str, alive: bool = True) -> HostScanResult:
    return HostScanResult(
        target=target,
        is_alive=alive,
        open_ports=[80],
        os_guess="Linux",
        os_accuracy=90,
        high_ports=[50000],
        score_breakdown={"icmp": 2},
        score=5,
        priority="High",
        errors=[ErrorRecord(code="E1", message_key="m", action_key="a")],
        detail_level="fast",
        detail_updated_at="now",
    )


# ---------- privileges tests ----------


def test_has_required_privileges_respects_platform(monkeypatch):
    assert privileges.has_required_privileges({ScanMode.ICMP}) is True

    monkeypatch.setattr(privileges, "os", SimpleNamespace(name="nt"))
    assert privileges.has_required_privileges({ScanMode.OS}) is True

    monkeypatch.setattr(privileges, "os", SimpleNamespace(name="posix", geteuid=lambda: 1))
    assert privileges.has_required_privileges({ScanMode.OS}) is False

    monkeypatch.setattr(privileges, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    assert privileges.has_required_privileges({ScanMode.OS}) is True


def test_privileged_launch_command_handles_frozen(monkeypatch, tmp_path):
    exe = tmp_path / "rogue-finder"
    exe.write_text("placeholder")
    monkeypatch.setattr(privileges.sys, "frozen", True, raising=False)
    monkeypatch.setattr(privileges.sys, "executable", str(exe))
    command = privileges.privileged_launch_command()
    assert str(exe) in command

    monkeypatch.setattr(privileges.sys, "frozen", False, raising=False)
    monkeypatch.setattr(privileges.sys, "executable", str(exe))
    result = privileges.privileged_launch_command()
    assert "-m nmap_gui.main" in result


def test_show_privileged_hint_uses_translator(monkeypatch):
    calls: list[tuple[object, str, str]] = []

    class FakeMessageBox:
        @staticmethod
        def information(parent, title, body):
            calls.append((parent, title, body))

    monkeypatch.setattr(privileges, "QMessageBox", FakeMessageBox)
    monkeypatch.setattr(privileges, "privileged_launch_command", lambda: "sudo ./rogue")

    translations = {
        "privileged_os_required_title": "Need privileges",
        "privileged_os_required_body": "Run: {command}",
    }

    def translate(key: str) -> str:
        return translations[key]

    sentinel_parent = object()
    privileges.show_privileged_hint(sentinel_parent, translate)

    assert calls == [(sentinel_parent, "Need privileges", "Run: sudo ./rogue")]


# ---------- ResultStore tests ----------


class StubResultGrid:
    def __init__(self):
        self.reset_calls: list[bool] = []
        self.updated: list[tuple[str, bool]] = []
        self.selections: list[tuple[set[str], set[str], bool]] = []
        self._advanced: set[str] = set()
        self._safety: set[str] = set()

    def reset(self, *, emit_signal: bool = True) -> None:
        self.reset_calls.append(emit_signal)

    def update_result(self, result: HostScanResult, allow_sort_restore: bool = True) -> None:
        self.updated.append((result.target, allow_sort_restore))

    def set_selections(self, *, advanced: set[str], safety: set[str], emit_signal: bool) -> None:
        self.selections.append((set(advanced), set(safety), emit_signal))
        self._advanced = set(advanced)
        self._safety = set(safety)

    def advanced_targets(self) -> set[str]:
        return set(self._advanced)

    def safety_targets(self) -> set[str]:
        return set(self._safety)


class StubSummaryPanel:
    def __init__(self):
        self.calls: list[dict[str, int | str]] = []

    def update_summary(
        self,
        *,
        target_count: int,
        requested_hosts: int,
        discovered_hosts: int,
        alive_hosts: int,
        status: str,
    ) -> None:
        self.calls.append(
            {
                "target_count": target_count,
                "requested_hosts": requested_hosts,
                "discovered_hosts": discovered_hosts,
                "alive_hosts": alive_hosts,
                "status": status,
            }
        )


def test_result_store_add_update_and_snapshot():
    grid = StubResultGrid()
    summary = StubSummaryPanel()
    store = result_store_mod.ResultStore(grid, summary)

    base = _make_result("alpha", alive=False)
    updated = _make_result("alpha", alive=True)
    updated.detail_level = "advanced"
    updated.detail_updated_at = "later"

    stored = store.add_or_update(base)
    updated_ref = store.add_or_update(updated)

    assert stored is updated_ref
    assert stored.is_alive is True
    assert grid.updated == [("alpha", True), ("alpha", True)]

    snapshot = store.snapshot_results()
    snapshot[0].target = "modified"
    assert store.results()[0].target == "alpha"

    store.reset(emit_selection_changed=False)
    assert grid.reset_calls == [False]
    assert not store.has_results()


def test_result_store_diagnostics_helpers():
    grid = StubResultGrid()
    summary = StubSummaryPanel()
    store = result_store_mod.ResultStore(grid, summary)

    store.add_or_update(_make_result("bravo"))
    store.set_diagnostics_status("bravo", "completed", "now")
    store.set_diagnostics_report(
        "bravo",
        SafeScanReport(
            target="bravo",
            command="nmap",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        ),
    )
    report = store.diagnostics_report_for("bravo")
    assert report is not None
    assert grid.updated[-1] == ("bravo", False)


def test_result_store_restore_and_summary():
    grid = StubResultGrid()
    summary = StubSummaryPanel()
    store = result_store_mod.ResultStore(grid, summary)

    stored = [_make_result("charlie"), _make_result("delta", alive=False)]
    store.restore_results(stored)
    assert {result.target for result in store.results()} == {"charlie", "delta"}

    store.update_summary(target_count=4, requested_hosts=10, status="running")
    assert summary.calls[-1]["alive_hosts"] == 1
    assert summary.calls[-1]["discovered_hosts"] == 2


# ---------- StateController tests ----------


class StubWindow:
    def __init__(self):
        self.restored = []
        self.saved_geometry = b"window-bounds"
        self.closed = False

    def restoreGeometry(self, geometry):
        self.restored.append(geometry)

    def saveGeometry(self):
        return self.saved_geometry

    def close(self):
        self.closed = True


class StubControls:
    def __init__(self):
        self.text = ""

    def set_targets_text(self, value: str) -> None:
        self.text = value

    def targets_text(self) -> str:
        return self.text


class StubResultStore:
    def __init__(self):
        self.reset_calls: list[bool] = []
        self.restore_payloads: list[list[HostScanResult]] = []
        self.snapshots: list[list[HostScanResult]] = [[_make_result("epsilon")]]

    def reset(self, *, emit_selection_changed: bool = True) -> None:
        self.reset_calls.append(emit_selection_changed)

    def restore_results(self, results):
        self.restore_payloads.append(list(results))

    def snapshot_results(self) -> list[HostScanResult]:
        return self.snapshots[-1]


def _translator_factory() -> Callable[[str], str]:
    translations = {
        "storage_warning_title": "Storage Warning",
        "storage_warning_body": "Please review",
        "storage_warning_line": "{scope}:{action}:{path}:{detail}",
        "storage_warning_continue": "Continue",
        "storage_warning_exit": "Exit",
        "storage_scope_state": "State",
        "storage_action_write": "Write",
    }

    def _translate(key: str) -> str:
        return translations.get(key, key)

    return _translate


def test_state_controller_initialize_apply_and_collect(monkeypatch):
    controller = state_controller_mod.StateController(_translator_factory())
    provided_state = AppState(
        targets_text="10.0.0.0/24",
        window_geometry=b"geo",
        advanced_selected={"alpha"},
        safety_selected={"bravo"},
        results=[_make_result("alpha")],
    )

    assert controller.initialize(provided_state) is provided_state

    window = StubWindow()
    controls = StubControls()
    result_store = StubResultStore()
    grid = StubResultGrid()

    controller.apply(window=window, controls=controls, result_store=result_store, result_grid=grid)

    collected = controller.collect(window=window, controls=controls, result_store=result_store, result_grid=grid)
    assert collected.targets_text == "10.0.0.0/24"
    assert controls.targets_text() == "10.0.0.0/24"


def test_state_controller_persist_handles_failure(monkeypatch):
    controller = state_controller_mod.StateController(_translator_factory())
    window = StubWindow()
    controls = StubControls()
    result_store = StubResultStore()
    grid = StubResultGrid()

    monkeypatch.setattr(state_controller_mod, "save_state", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        state_controller_mod.StateController,
        "_prompt_storage_warnings",
        lambda self, window: False,
    )
    single_shots: list[tuple[int, object]] = []
    monkeypatch.setattr(state_controller_mod.QTimer, "singleShot", lambda delay, callback: single_shots.append((delay, callback)))

    assert controller.persist(
        window=window,
        controls=controls,
        result_store=result_store,
        result_grid=grid,
        on_close=False,
    )
    assert single_shots == [(0, window.close)]

    assert controller.persist(
        window=window,
        controls=controls,
        result_store=result_store,
        result_grid=grid,
        on_close=True,
    ) is True

    controller_success = state_controller_mod.StateController(_translator_factory())
    monkeypatch.setattr(state_controller_mod, "save_state", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        state_controller_mod.StateController,
        "_prompt_storage_warnings",
        lambda self, window: True,
    )
    assert controller_success.persist(
        window=window,
        controls=controls,
        result_store=result_store,
        result_grid=grid,
        on_close=True,
    ) is False


def test_state_controller_prompt_storage_warnings(monkeypatch):
    controller = state_controller_mod.StateController(_translator_factory())
    warnings = [
        StorageWarning(scope="state", action="write", path=Path("/tmp/state"), detail="disk full"),
    ]
    monkeypatch.setattr(state_controller_mod, "consume_storage_warnings", lambda: warnings)

    class FakeMessageBox:
        Warning = "warning"

        class ButtonRole:
            AcceptRole = "accept"
            RejectRole = "reject"

        next_result = "accept"

        def __init__(self, *_):
            self.accept_button = object()
            self.reject_button = object()

        def setIcon(self, *_):
            pass

        def setWindowTitle(self, *_):
            pass

        def setText(self, *_):
            pass

        def setInformativeText(self, *_):
            pass

        def addButton(self, label, role):
            return self.accept_button if role == self.ButtonRole.AcceptRole else self.reject_button

        def setDefaultButton(self, *_):
            pass

        def exec(self):
            pass

        def clickedButton(self):
            return self.accept_button if self.next_result == "accept" else self.reject_button

    monkeypatch.setattr(state_controller_mod, "QMessageBox", FakeMessageBox)

    window = StubWindow()
    assert controller._prompt_storage_warnings(window) is True
    assert controller.persistence_enabled() is False

    FakeMessageBox.next_result = "reject"
    assert controller._prompt_storage_warnings(window) is False
