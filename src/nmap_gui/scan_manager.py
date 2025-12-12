"""Scan orchestration layer bridging GUI and multiprocessing workers."""
from __future__ import annotations

import multiprocessing as mp
import os
import sys
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from contextlib import suppress
from functools import partial
from threading import Thread

try:  # Python embedded in PyInstaller on Windows may lack BrokenProcessPool
    from concurrent.futures import BrokenProcessPool
except ImportError:  # pragma: no cover - fallback for runtimes missing the class
    class BrokenProcessPool(RuntimeError):  # type: ignore[override]
        """Compatibility placeholder so exception handling still works."""
from multiprocessing.connection import Connection
from typing import Dict, Optional, Sequence

from PySide6.QtCore import QObject, QThread, Signal, Slot

from .config import AppSettings, get_settings
from .error_codes import (
    ERROR_SCAN_CRASHED,
    ERROR_WORKER_POOL_FAILED,
    build_error,
)
from .models import ScanConfig, ScanLogEvent
from .nmap_runner import run_full_scan, run_safe_script_scan
from .cancel_token import PipeCancelToken, create_pipe_cancel_token


def _send_log_event(connection: Connection | None, event: ScanLogEvent) -> None:
    if connection is None:
        return
    with suppress(BrokenPipeError, OSError):
        connection.send(event)


def _should_use_threads() -> bool:
    """Return True when multiprocessing executors are known to be unstable."""

    return os.name == "nt" or sys.platform == "darwin"


class ScanWorker(QObject):
    progress = Signal(int, int)
    result_ready = Signal(object)
    error = Signal(object)
    finished = Signal()
    log_ready = Signal(object)

    def __init__(self, config: ScanConfig, settings: AppSettings | None = None):
        super().__init__()
        self._config = config
        self._settings = settings or get_settings()
        self._mp_context = mp.get_context("spawn")
        self._cancel_tx: Optional[Connection] = None
        self._cancel_token: Optional[PipeCancelToken] = None
        self._init_cancel_token()
        self._use_threads = _should_use_threads()
        self._log_receivers: list[Connection] = []
        self._log_threads: list[Thread] = []

    @Slot()
    def start(self) -> None:
        targets = self._prepare_targets()
        total = len(targets)
        if not targets:
            self.finished.emit()
            self._close_cancel_token()
            return
        executor_cls, executor_kwargs = self._executor_config(total)
        try:
            with executor_cls(**executor_kwargs) as executor:
                futures, log_channels = self._submit_targets(executor, targets)
                self._consume_futures(futures, log_channels, total)
        finally:
            self.finished.emit()
            self._close_cancel_token()
            self._close_log_receivers()

    def request_stop(self) -> None:
        if self._cancel_tx is not None:
            with suppress(OSError, BrokenPipeError):
                self._cancel_tx.send(True)

    def _init_cancel_token(self) -> None:
        tx, token = create_pipe_cancel_token(self._mp_context)
        self._cancel_tx = tx
        self._cancel_token = token

    def _close_cancel_token(self) -> None:
        if self._cancel_tx is not None:
            self._cancel_tx.close()
        self._cancel_tx = None
        if self._cancel_token is not None:
            self._cancel_token.close()
        self._cancel_token = None

    def _create_log_channel(self) -> Connection | None:
        try:
            rx, tx = self._mp_context.Pipe(duplex=False)
        except (OSError, ValueError):
            return None
        thread = Thread(target=self._relay_log_events, args=(rx,), daemon=True)
        thread.start()
        self._log_receivers.append(rx)
        self._log_threads.append(thread)
        return tx

    def _relay_log_events(self, connection: Connection) -> None:
        try:
            while True:
                try:
                    event = connection.recv()
                except (EOFError, OSError, ValueError):
                    break
                else:
                    self.log_ready.emit(event)
        finally:
            with suppress(OSError):
                connection.close()

    def _close_log_receivers(self) -> None:
        for conn in self._log_receivers:
            with suppress(OSError):
                conn.close()
        self._log_receivers.clear()
        for thread in self._log_threads:
            thread.join(timeout=0.1)
        self._log_threads.clear()

    def _prepare_targets(self) -> list[str]:
        return list(dict.fromkeys(self._config.targets))

    def _executor_config(
        self, total: int
    ) -> tuple[type[ThreadPoolExecutor] | type[ProcessPoolExecutor], Dict[str, object]]:
        configured_max = self._config.max_parallel or (os.cpu_count() or 1)
        max_workers = max(1, min(total, configured_max))
        executor_kwargs: Dict[str, object] = {"max_workers": max_workers}
        executor_cls = ThreadPoolExecutor if self._use_threads else ProcessPoolExecutor
        if not self._use_threads:
            executor_kwargs["mp_context"] = self._mp_context
        return executor_cls, executor_kwargs

    def _submit_targets(
        self,
        executor,
        targets: Sequence[str],
    ) -> tuple[Dict[object, str], Dict[object, Connection]]:
        futures: Dict[object, str] = {}
        log_channels: Dict[object, Connection] = {}
        for target in targets:
            connection = self._create_log_channel()
            log_callback = partial(_send_log_event, connection) if connection else None
            try:
                future = executor.submit(
                    run_full_scan,
                    target,
                    self._config.scan_modes,
                    self._cancel_token,
                    log_callback,
                    self._settings,
                    self._config.port_list,
                    self._config.timeout_seconds,
                    self._config.detail_label,
                )
            except Exception:
                if connection is not None:
                    with suppress(OSError):
                        connection.close()
                raise
            futures[future] = target
            if connection is not None:
                log_channels[future] = connection
        return futures, log_channels

    def _consume_futures(
        self,
        futures: Dict[object, str],
        log_channels: Dict[object, Connection],
        total: int,
    ) -> None:
        for completed, future in enumerate(as_completed(futures), start=1):
            if self._cancelled():
                break
            try:
                result = future.result()
                if isinstance(result, list):
                    for payload in result:
                        self.result_ready.emit(payload)
                else:
                    self.result_ready.emit(result)
            except BrokenProcessPool as exc:
                self.error.emit(
                    build_error(
                        ERROR_WORKER_POOL_FAILED,
                        detail=str(exc),
                    )
                )
                break
            except Exception as exc:  # noqa: BLE001
                self.error.emit(build_error(ERROR_SCAN_CRASHED, detail=str(exc)))
            self.progress.emit(completed, total)
            if self._cancelled():
                break
            self._close_single_log_channel(log_channels.pop(future, None))
        for conn in log_channels.values():
            self._close_single_log_channel(conn)

    def _close_single_log_channel(self, connection: Connection | None) -> None:
        if connection is not None:
            with suppress(OSError):
                connection.close()

    def _cancelled(self) -> bool:
        return bool(self._cancel_token and self._cancel_token.is_set())


class ScanManager(QObject):
    progress = Signal(int, int)
    result_ready = Signal(object)
    error = Signal(object)
    started = Signal(int)
    finished = Signal()
    log_ready = Signal(object)

    def __init__(self, settings: AppSettings | None = None) -> None:
        super().__init__()
        self._settings = settings or get_settings()
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None

    def start(self, config: ScanConfig) -> None:
        self.stop()
        self._thread = QThread()
        self._worker = ScanWorker(config, self._settings)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.start)
        self._worker.progress.connect(self.progress)
        self._worker.result_ready.connect(self.result_ready)
        self._worker.error.connect(self.error)
        self._worker.log_ready.connect(self.log_ready)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self.finished)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()
        self.started.emit(len(config.targets))

    def stop(self) -> None:
        if self._worker:
            self._worker.request_stop()
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(2000)
        self._cleanup_thread()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.isRunning())

    def _cleanup_thread(self) -> None:
        self._worker = None
        if self._thread:
            self._thread.deleteLater()
        self._thread = None

    def update_settings(self, settings: AppSettings) -> None:
        self._settings = settings


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
                    except Exception as exc:  # noqa: BLE001
                        self.error.emit(exc)
                    else:
                        self.result_ready.emit(report)
                    self.progress.emit(completed, total)
        finally:
            self.finished.emit()


class SafeScriptManager(QObject):
    progress = Signal(int, int)
    result_ready = Signal(object)
    error = Signal(object)
    started = Signal(int)
    finished = Signal()

    def __init__(self, settings: AppSettings | None = None) -> None:
        super().__init__()
        self._settings = settings or get_settings()
        self._thread: QThread | None = None
        self._worker: SafeScriptWorker | None = None

    def start(self, targets: Sequence[str]) -> None:
        if self.is_running():
            return
        unique_targets = list(dict.fromkeys(targets))
        if not unique_targets:
            return
        self._thread = QThread()
        self._worker = SafeScriptWorker(unique_targets, self._settings)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.start)
        self._worker.result_ready.connect(self.result_ready)
        self._worker.error.connect(self.error)
        self._worker.progress.connect(self.progress)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self.finished)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()
        self.started.emit(len(unique_targets))

    def stop(self) -> None:
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(2000)
        self._cleanup_thread()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.isRunning())

    def _cleanup_thread(self) -> None:
        self._worker = None
        if self._thread:
            self._thread.deleteLater()
        self._thread = None

    def update_settings(self, settings: AppSettings) -> None:
        self._settings = settings
