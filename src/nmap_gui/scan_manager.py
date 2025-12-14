"""Scan orchestration layer bridging GUI and multiprocessing workers."""
from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Protocol

from PySide6.QtCore import QObject, QThread, Signal, Slot

from .infrastructure.config import AppSettings, get_settings
from .models import ScanConfig, ScanLogEvent
from .nmap_runner import run_safe_script_scan
from .scan_executor import ScanJobCallbacks, ScanJobExecutor

try:  # Windows-only helper; importing on other platforms raises.
    from .privileged_runner import PrivilegedRunnerBackend
except Exception:  # pragma: no cover - on non-Windows hosts this import fails
    PrivilegedRunnerBackend = None  # type: ignore[assignment]


class ScanWorker(QObject):
    progress = Signal(int, int)
    result_ready = Signal(object)
    error = Signal(object)
    finished = Signal()
    log_ready = Signal(object)

    def __init__(self, config: ScanConfig, settings: AppSettings | None = None) -> None:
        super().__init__()
        self._config = config
        self._settings = settings or get_settings()
        self._executor = ScanJobExecutor(self._settings)

    @Slot()
    def start(self) -> None:
        callbacks = ScanJobCallbacks(
            on_progress=self._emit_progress,
            on_result=self._emit_result,
            on_error=self._emit_error,
            on_log=self._emit_log,
        )
        try:
            self._executor.run(self._config, callbacks)
        finally:
            self.finished.emit()

    def request_stop(self) -> None:
        self._executor.cancel()

    def _emit_progress(self, completed: int, total: int) -> None:
        self.progress.emit(completed, total)

    def _emit_result(self, payload) -> None:
        self.result_ready.emit(payload)

    def _emit_error(self, payload) -> None:
        self.error.emit(payload)

    def _emit_log(self, event: ScanLogEvent) -> None:
        self.log_ready.emit(event)


@dataclass(slots=True)
class ScanCallbacks:
    on_started: Callable[[int], None]
    on_progress: Callable[[int, int], None]
    on_result: Callable[[object], None]
    on_error: Callable[[object], None]
    on_finished: Callable[[], None]
    on_log: Callable[[ScanLogEvent], None] | None = None


class ScanBackend(Protocol):
    def start(self, config: ScanConfig, callbacks: ScanCallbacks) -> None:  # pragma: no cover - protocol
        ...

    def stop(self) -> None:  # pragma: no cover - protocol
        ...

    def is_running(self) -> bool:  # pragma: no cover - protocol
        ...

    def update_settings(self, settings: AppSettings) -> None:  # pragma: no cover - protocol
        ...


class DirectScanBackend(ScanBackend):
    def __init__(self, settings: AppSettings | None = None) -> None:
        self._settings = settings or get_settings()
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self._callbacks: ScanCallbacks | None = None

    def start(self, config: ScanConfig, callbacks: ScanCallbacks) -> None:
        self.stop()
        self._callbacks = callbacks
        self._thread = QThread()
        self._worker = ScanWorker(config, self._settings)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.start)
        self._worker.progress.connect(self._emit_progress)
        self._worker.result_ready.connect(self._emit_result)
        self._worker.error.connect(self._emit_error)
        self._worker.log_ready.connect(self._emit_log)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._handle_worker_finished)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()

    def stop(self) -> None:
        if self._worker:
            self._worker.request_stop()
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(2000)
        self._cleanup_thread()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.isRunning())

    def update_settings(self, settings: AppSettings) -> None:
        self._settings = settings

    def _emit_progress(self, completed: int, total: int) -> None:
        if self._callbacks:
            self._callbacks.on_progress(completed, total)

    def _emit_result(self, payload) -> None:
        if self._callbacks:
            self._callbacks.on_result(payload)

    def _emit_error(self, payload) -> None:
        if self._callbacks:
            self._callbacks.on_error(payload)

    def _emit_log(self, event) -> None:
        if self._callbacks and self._callbacks.on_log:
            self._callbacks.on_log(event)

    def _handle_worker_finished(self) -> None:
        callbacks = self._callbacks
        self._callbacks = None
        if callbacks:
            callbacks.on_finished()

    def _cleanup_thread(self) -> None:
        self._worker = None
        if self._thread:
            self._thread.deleteLater()
        self._thread = None


class PrivilegedScanBackend(ScanBackend):
    def __init__(self, settings: AppSettings | None = None) -> None:
        if PrivilegedRunnerBackend is None:  # pragma: no cover - platform guard
            raise RuntimeError("Privileged runner backend unavailable on this platform")
        self._settings = settings or get_settings()
        self._backend = PrivilegedRunnerBackend(self._settings)

    def start(self, config: ScanConfig, callbacks: ScanCallbacks) -> None:
        runner_callbacks = _RunnerCallbackProxy.from_scan_callbacks(callbacks)
        self._backend.start(config, runner_callbacks)

    def stop(self) -> None:
        self._backend.stop()

    def is_running(self) -> bool:
        return self._backend.is_running()

    def update_settings(self, settings: AppSettings) -> None:
        self._settings = settings
        self._backend.update_settings(settings)

    def close(self) -> None:
        self._backend.close()


@dataclass(slots=True)
class _RunnerCallbackProxy:
    on_progress: Callable[[int, int], None] | None = None
    on_result: Callable[[object], None] | None = None
    on_error: Callable[[object], None] | None = None
    on_finished: Callable[[], None] | None = None
    on_log: Callable[[ScanLogEvent], None] | None = None

    @staticmethod
    def from_scan_callbacks(callbacks: ScanCallbacks) -> _RunnerCallbackProxy:
        return _RunnerCallbackProxy(
            on_progress=callbacks.on_progress,
            on_result=callbacks.on_result,
            on_error=callbacks.on_error,
            on_finished=callbacks.on_finished,
            on_log=callbacks.on_log,
        )


class ScanManager:
    def __init__(
        self,
        settings: AppSettings | None = None,
        backend: ScanBackend | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._backend = backend or self._create_backend(self._settings)

    def start(self, config: ScanConfig, callbacks: ScanCallbacks) -> None:
        self.stop()
        self._backend.start(config, callbacks)
        callbacks.on_started(len(config.targets))

    def stop(self) -> None:
        self._backend.stop()

    def is_running(self) -> bool:
        return self._backend.is_running()

    def update_settings(self, settings: AppSettings) -> None:
        self._settings = settings
        if self._requires_backend_swap(settings):
            self._swap_backend(self._create_backend(settings))
        else:
            self._backend.update_settings(settings)

    def _requires_backend_swap(self, settings: AppSettings) -> bool:
        wants_privileged = self._should_use_privileged_backend(settings)
        is_privileged_backend = isinstance(self._backend, PrivilegedScanBackend)
        return wants_privileged != is_privileged_backend

    def _swap_backend(self, new_backend: ScanBackend) -> None:
        old_backend = self._backend
        old_backend.stop()
        close_fn = getattr(old_backend, "close", None)
        if callable(close_fn):
            close_fn()
        self._backend = new_backend

    def _create_backend(self, settings: AppSettings) -> ScanBackend:
        if self._should_use_privileged_backend(settings):
            return PrivilegedScanBackend(settings)
        return DirectScanBackend(settings)

    @staticmethod
    def _should_use_privileged_backend(settings: AppSettings) -> bool:
        return (
            sys.platform == "win32"
            and settings.runtime.windows_privileged_runner
            and PrivilegedRunnerBackend is not None
        )


class SafeScriptWorker(QObject):
    progress = Signal(int, int)
    result_ready = Signal(object)
    error = Signal(object)
    finished = Signal()

    def __init__(self, targets: Sequence[str], settings: AppSettings | None = None):
        super().__init__()
        self._targets = list(dict.fromkeys(targets))
        self._settings = settings or get_settings()

    @Slot()
    def start(self) -> None:
        total = len(self._targets)
        if total == 0:
            self.finished.emit()
            return
        timeout = self._settings.safe_scan.timeout_seconds
        max_workers = max(1, self._settings.safe_scan.max_parallel)
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        run_safe_script_scan,
                        target,
                        timeout,
                        self._settings,
                    ): target
                    for target in self._targets
                }
                for completed, future in enumerate(as_completed(futures), start=1):
                    try:
                        report = future.result()
                    except Exception as exc:
                        self.error.emit(exc)
                    else:
                        self.result_ready.emit(report)
                    self.progress.emit(completed, total)
        finally:
            self.finished.emit()


@dataclass(slots=True)
class SafeScriptCallbacks:
    on_started: Callable[[int], None]
    on_progress: Callable[[int, int], None]
    on_result: Callable[[object], None]
    on_error: Callable[[object], None]
    on_finished: Callable[[], None]


class SafeScriptBackend(Protocol):
    def start(self, targets: Sequence[str], callbacks: SafeScriptCallbacks) -> None:  # pragma: no cover - protocol
        ...

    def stop(self) -> None:  # pragma: no cover - protocol
        ...

    def is_running(self) -> bool:  # pragma: no cover - protocol
        ...

    def update_settings(self, settings: AppSettings) -> None:  # pragma: no cover - protocol
        ...


class DirectSafeScriptBackend(SafeScriptBackend):
    def __init__(self, settings: AppSettings | None = None) -> None:
        self._settings = settings or get_settings()
        self._thread: QThread | None = None
        self._worker: SafeScriptWorker | None = None
        self._callbacks: SafeScriptCallbacks | None = None

    def start(self, targets: Sequence[str], callbacks: SafeScriptCallbacks) -> None:
        if self.is_running():
            return
        self._callbacks = callbacks
        self._thread = QThread()
        self._worker = SafeScriptWorker(targets, self._settings)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.start)
        self._worker.result_ready.connect(self._emit_result)
        self._worker.error.connect(self._emit_error)
        self._worker.progress.connect(self._emit_progress)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._handle_finished)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()

    def stop(self) -> None:
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(2000)
        self._cleanup_thread()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.isRunning())

    def update_settings(self, settings: AppSettings) -> None:
        self._settings = settings

    def _emit_result(self, payload) -> None:
        if self._callbacks:
            self._callbacks.on_result(payload)

    def _emit_error(self, payload) -> None:
        if self._callbacks:
            self._callbacks.on_error(payload)

    def _emit_progress(self, completed: int, total: int) -> None:
        if self._callbacks:
            self._callbacks.on_progress(completed, total)

    def _handle_finished(self) -> None:
        callbacks = self._callbacks
        self._callbacks = None
        if callbacks:
            callbacks.on_finished()

    def _cleanup_thread(self) -> None:
        self._worker = None
        if self._thread:
            self._thread.deleteLater()
        self._thread = None


class SafeScriptManager:
    def __init__(
        self,
        settings: AppSettings | None = None,
        backend: SafeScriptBackend | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._backend = backend or DirectSafeScriptBackend(self._settings)

    def start(self, targets: Sequence[str], callbacks: SafeScriptCallbacks) -> None:
        if self._backend.is_running():
            return
        unique_targets = list(dict.fromkeys(targets))
        if not unique_targets:
            return
        self._backend.start(unique_targets, callbacks)
        callbacks.on_started(len(unique_targets))

    def stop(self) -> None:
        self._backend.stop()

    def is_running(self) -> bool:
        return self._backend.is_running()

    def update_settings(self, settings: AppSettings) -> None:
        self._settings = settings
        self._backend.update_settings(settings)
