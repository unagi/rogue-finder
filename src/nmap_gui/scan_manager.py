"""Scan orchestration layer bridging GUI and multiprocessing workers."""
from __future__ import annotations

import multiprocessing as mp
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing.connection import Connection
from typing import Optional

from PySide6.QtCore import QObject, QThread, Signal, Slot

from .models import ScanConfig
from .nmap_runner import run_full_scan
from .cancel_token import PipeCancelToken, create_pipe_cancel_token


class ScanWorker(QObject):
    progress = Signal(int, int)
    result_ready = Signal(object)
    error = Signal(str)
    finished = Signal()

    def __init__(self, config: ScanConfig):
        super().__init__()
        self._config = config
        self._mp_context = mp.get_context("spawn")
        self._cancel_tx: Optional[Connection] = None
        self._cancel_token: Optional[PipeCancelToken] = None
        self._init_cancel_token()

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
            with ProcessPoolExecutor(max_workers=max_workers, mp_context=ctx) as executor:
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
                        self.result_ready.emit(result)
                    except Exception as exc:  # noqa: BLE001
                        self.error.emit(f"Scan failed: {exc}")
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
    error = Signal(str)
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
