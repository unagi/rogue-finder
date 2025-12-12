"""App state load/save helper."""
from __future__ import annotations

from contextlib import suppress
from typing import Callable

from PySide6.QtCore import QByteArray, QTimer
from PySide6.QtWidgets import QMainWindow, QMessageBox

from ..result_grid import ResultGrid
from ..state_store import AppState, load_state, save_state
from ..storage_warnings import StorageWarning, consume_storage_warnings
from .scan_controls import ScanControlsPanel
from .result_store import ResultStore

Translator = Callable[[str], str]


class StateController:
    def __init__(self, translator: Translator) -> None:
        self._translator = translator
        self._app_state = AppState()
        self._disable_persistence = False

    @property
    def app_state(self) -> AppState:
        return self._app_state

    def initialize(self, provided: AppState | None) -> AppState:
        if provided:
            self._app_state = provided
            return self._app_state
        state = load_state()
        if state:
            self._app_state = state
            return self._app_state
        state = AppState()
        if not save_state(state):
            self._disable_persistence = True
        self._app_state = state
        return self._app_state

    def apply(self, *, window: QMainWindow, controls: ScanControlsPanel, result_store: ResultStore, result_grid: ResultGrid) -> None:
        state = self._app_state
        controls.set_targets_text(state.targets_text)
        if state.window_geometry:
            with suppress(TypeError):
                window.restoreGeometry(QByteArray(state.window_geometry))
        result_store.reset(emit_selection_changed=False)
        result_grid.set_selections(
            advanced=state.advanced_selected,
            os_targets=state.os_selected,
            safety=state.safety_selected,
            emit_signal=False,
        )
        result_store.restore_results(state.results)

    def collect(self, *, window: QMainWindow, controls: ScanControlsPanel, result_store: ResultStore, result_grid: ResultGrid) -> AppState:
        return AppState(
            targets_text=controls.targets_text(),
            icmp_enabled=True,
            ports_enabled=True,
            os_enabled=False,
            window_geometry=bytes(window.saveGeometry()),
            results=result_store.snapshot_results(),
            advanced_selected=result_grid.advanced_targets(),
            os_selected=result_grid.os_targets(),
            safety_selected=result_grid.safety_targets(),
        )

    def persist(
        self,
        *,
        window: QMainWindow,
        controls: ScanControlsPanel,
        result_store: ResultStore,
        result_grid: ResultGrid,
        state: AppState | None = None,
        on_close: bool = False,
    ) -> bool:
        if self._disable_persistence:
            return True
        snapshot = state or self.collect(
            window=window,
            controls=controls,
            result_store=result_store,
            result_grid=result_grid,
        )
        saved = save_state(snapshot)
        if saved:
            self._app_state = snapshot
            return True
        self._disable_persistence = True
        keep_running = self._prompt_storage_warnings(window)
        if on_close:
            return not keep_running
        if not keep_running:
            QTimer.singleShot(0, window.close)
        return True

    def persistence_enabled(self) -> bool:
        return not self._disable_persistence

    def prompt_storage_warnings(self, window: QMainWindow) -> bool:
        return self._prompt_storage_warnings(window)

    def _prompt_storage_warnings(self, window: QMainWindow) -> bool:
        warnings = consume_storage_warnings()
        if not warnings:
            return True
        if any(w.scope == "state" for w in warnings):
            self._disable_persistence = True
        detail_text = "\n\n".join(self._format_storage_warning(w) for w in warnings)
        dialog = QMessageBox(window)
        dialog.setIcon(QMessageBox.Warning)
        dialog.setWindowTitle(self._translator("storage_warning_title"))
        dialog.setText(self._translator("storage_warning_body"))
        dialog.setInformativeText(detail_text)
        continue_button = dialog.addButton(
            self._translator("storage_warning_continue"), QMessageBox.ButtonRole.AcceptRole
        )
        dialog.addButton(self._translator("storage_warning_exit"), QMessageBox.ButtonRole.RejectRole)
        dialog.setDefaultButton(continue_button)
        dialog.exec()
        return dialog.clickedButton() is continue_button

    def _format_storage_warning(self, warning: StorageWarning) -> str:
        scope_label = self._storage_scope_label(warning.scope)
        action_label = self._storage_action_label(warning.action)
        return self._translator("storage_warning_line").format(
            scope=scope_label,
            action=action_label,
            path=str(warning.path),
            detail=warning.detail,
        )

    def _storage_scope_label(self, scope: str) -> str:
        key = f"storage_scope_{scope}"
        label = self._translator(key)
        return label if label != key else scope

    def _storage_action_label(self, action: str) -> str:
        key = f"storage_action_{action}"
        label = self._translator(key)
        return label if label != key else action
