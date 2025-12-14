"""Qt-facing controllers that bridge GUI signals to scan managers."""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from .infrastructure.config import AppSettings, get_settings
from .models import ScanLogEvent
from .scan_manager import (
    SafeScriptCallbacks,
    SafeScriptManager,
    ScanCallbacks,
    ScanManager,
)


class ScanController(QObject):
    progress = Signal(int, int)
    result_ready = Signal(object)
    error = Signal(object)
    started = Signal(int)
    finished = Signal()
    log_ready = Signal(object)

    def __init__(
        self,
        settings: AppSettings | None = None,
        manager: ScanManager | None = None,
    ) -> None:
        super().__init__()
        resolved_settings = settings or get_settings()
        self._manager = manager or ScanManager(resolved_settings)

    def start(self, config) -> None:
        callbacks = ScanCallbacks(
            on_started=self.started.emit,
            on_progress=self.progress.emit,
            on_result=self.result_ready.emit,
            on_error=self.error.emit,
            on_finished=self.finished.emit,
            on_log=self._emit_log,
        )
        self._manager.start(config, callbacks)

    def stop(self) -> None:
        self._manager.stop()

    def is_running(self) -> bool:
        return self._manager.is_running()

    def update_settings(self, settings: AppSettings) -> None:
        self._manager.update_settings(settings)

    def _emit_log(self, event: ScanLogEvent) -> None:
        self.log_ready.emit(event)


class SafeScriptController(QObject):
    progress = Signal(int, int)
    result_ready = Signal(object)
    error = Signal(object)
    started = Signal(int)
    finished = Signal()

    def __init__(
        self,
        settings: AppSettings | None = None,
        manager: SafeScriptManager | None = None,
    ) -> None:
        super().__init__()
        resolved_settings = settings or get_settings()
        self._manager = manager or SafeScriptManager(resolved_settings)

    def start(self, targets) -> None:
        callbacks = SafeScriptCallbacks(
            on_started=self.started.emit,
            on_progress=self.progress.emit,
            on_result=self.result_ready.emit,
            on_error=self.error.emit,
            on_finished=self.finished.emit,
        )
        self._manager.start(targets, callbacks)

    def stop(self) -> None:
        self._manager.stop()

    def is_running(self) -> bool:
        return self._manager.is_running()

    def update_settings(self, settings: AppSettings) -> None:
        self._manager.update_settings(settings)
