"""Scan orchestration layer bridging GUI and multiprocessing workers."""
from __future__ import annotations

import multiprocessing as mp
import os
import sys
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

try:  # Python embedded in PyInstaller on Windows may lack BrokenProcessPool
    from concurrent.futures import BrokenProcessPool
except ImportError:  # pragma: no cover - fallback for runtimes missing the class
    class BrokenProcessPool(RuntimeError):  # type: ignore[override]
        """Compatibility placeholder so exception handling still works."""
from multiprocessing.connection import Connection
from typing import Optional

from PySide6.QtCore import QObject, QThread, Signal, Slot

from .error_codes import (
    ERROR_SCAN_CRASHED,
    ERROR_WORKER_POOL_FAILED,
    build_error,
)
from .models import ScanConfig
from .nmap_runner import run_full_scan
from .cancel_token import PipeCancelToken, create_pipe_cancel_token


def _should_use_threads() -> bool:
    """Return True when multiprocessing executors are known to be unstable."""

    return os.name == "nt" or sys.platform == "darwin"


class ScanWorker(QObject):
    progress = Signal(int, int)
    result_ready = Signal(object)
    error = Signal(object)
    finished = Signal()

    def __init__(self, config: ScanConfig):
        super().__init__()
        self._config = config
        self._mp_context = mp.get_context("spawn")
        self._cancel_tx: Optional[Connection] = None
        self._cancel_token: Optional[PipeCancelToken] = None
        self._init_cancel_token()
        self._use_threads = _should_use_threads()

    @Slot()
    def start(self) -> None:
        targets = list(dict.fromkeys(self._config.targets))
        total = len(targets)
        if not targets:
            self.finished.emit()
            self._close_cancel_token()
            return
        ctx = self._mp_context
        max_workers = min(total, os.cpu_count() or 1)
        try:
            executor_kwargs = {"max_workers": max_workers}
            executor_cls = ThreadPoolExecutor if self._use_threads else ProcessPoolExecutor
            if not self._use_threads:
                executor_kwargs["mp_context"] = ctx
            with executor_cls(**executor_kwargs) as executor:
                futures = {
                    executor.submit(
                        run_full_scan,
                        target,
                        self._config.scan_modes,
                        self._cancel_token,
                    ): target
                    for target in targets
                }
                completed = 0
                for future in as_completed(futures):
                    if self._cancel_token and self._cancel_token.is_set():
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
                    completed += 1
                    self.progress.emit(completed, total)
                    if self._cancel_token and self._cancel_token.is_set():
                        break
        finally:
            self.finished.emit()
            self._close_cancel_token()

    def request_stop(self) -> None:
        if self._cancel_tx is not None:
            try:
                self._cancel_tx.send(True)
            except (OSError, BrokenPipeError):
                pass

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


class ScanManager(QObject):
    progress = Signal(int, int)
    result_ready = Signal(object)
    error = Signal(object)
    started = Signal(int)
    finished = Signal()

    def __init__(self) -> None:
        super().__init__()
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None

    def start(self, config: ScanConfig) -> None:
        self.stop()
        self._thread = QThread()
        self._worker = ScanWorker(config)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.start)
        self._worker.progress.connect(self.progress)
        self._worker.result_ready.connect(self.result_ready)
        self._worker.error.connect(self.error)
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

    def _cleanup_thread(self) -> None:
        self._worker = None
        if self._thread:
            self._thread.deleteLater()
        self._thread = None
