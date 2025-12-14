"""Shared scan execution helpers for GUI and privileged runner workflows."""
from __future__ import annotations

import multiprocessing as mp
import os
import sys
from collections.abc import Callable, Sequence
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from contextlib import suppress
from dataclasses import dataclass
from threading import Thread
from typing import Any

try:  # Python embedded in PyInstaller on Windows may lack BrokenProcessPool
    from concurrent.futures import BrokenProcessPool
except ImportError:  # pragma: no cover - fallback for runtimes missing the class
    class BrokenProcessPool(RuntimeError):  # type: ignore[override]
        """Compatibility placeholder so exception handling still works."""

from multiprocessing.connection import Connection

from .errors import ERROR_SCAN_CRASHED, ERROR_WORKER_POOL_FAILED, build_error
from .infrastructure.config import AppSettings, get_settings
from .models import HostScanResult, ScanConfig, ScanLogEvent
from .nmap_runner import run_full_scan
from .process import PipeCancelToken, create_pipe_cancel_token


@dataclass(slots=True)
class ScanJobCallbacks:
    on_progress: Callable[[int, int], None] | None = None
    on_result: Callable[[HostScanResult], None] | None = None
    on_error: Callable[[object], None] | None = None
    on_log: Callable[[ScanLogEvent], None] | None = None


class ScanJobExecutor:
    """Execute ScanConfig workloads using threads or processes."""

    def __init__(
        self,
        settings: AppSettings | None = None,
        context: mp.context.BaseContext | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._mp_context = context or mp.get_context("spawn")
        self._cancel_tx: Connection | None = None
        self._cancel_token: PipeCancelToken | None = None
        self._use_threads = _should_use_threads()
        self._log_receivers: list[Connection] = []
        self._log_threads: list[Thread] = []
        self._running = False

    def run(self, config: ScanConfig, callbacks: ScanJobCallbacks) -> None:
        if self._running:
            raise RuntimeError("ScanJobExecutor already running")
        targets = list(dict.fromkeys(config.targets))
        total = len(targets)
        self._init_cancel_token()
        self._running = True
        try:
            if total == 0:
                return
            executor_cls, executor_kwargs = self._executor_config(config, total)
            with executor_cls(**executor_kwargs) as executor:
                futures, log_channels = self._submit_targets(executor, targets, config, callbacks)
                self._consume_futures(futures, log_channels, total, callbacks)
        finally:
            self._running = False
            self._close_cancel_token()
            self._close_log_receivers()

    def cancel(self) -> None:
        if self._cancel_tx is not None:
            with suppress(OSError, BrokenPipeError):
                self._cancel_tx.send(True)

    def _executor_config(
        self,
        config: ScanConfig,
        total: int,
    ) -> tuple[type[ThreadPoolExecutor] | type[ProcessPoolExecutor], dict[str, Any]]:
        configured_max = config.max_parallel or (os.cpu_count() or 1)
        max_workers = max(1, min(total, configured_max))
        executor_kwargs: dict[str, Any] = {"max_workers": max_workers}
        executor_cls = ThreadPoolExecutor if self._use_threads else ProcessPoolExecutor
        if not self._use_threads:
            executor_kwargs["mp_context"] = self._mp_context
        return executor_cls, executor_kwargs

    def _submit_targets(
        self,
        executor,
        targets: Sequence[str],
        config: ScanConfig,
        callbacks: ScanJobCallbacks,
    ) -> tuple[dict[object, str], dict[object, Connection]]:
        futures: dict[object, str] = {}
        log_channels: dict[object, Connection] = {}
        for target in targets:
            connection = self._create_log_channel(callbacks.on_log)
            log_callback = (lambda event, conn=connection: _send_log_event(conn, event)) if connection else None
            try:
                future = executor.submit(
                    run_full_scan,
                    target,
                    config.scan_modes,
                    self._cancel_token,
                    log_callback,
                    self._settings,
                    config.port_list,
                    config.timeout_seconds,
                    config.detail_label,
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
        futures: dict[object, str],
        log_channels: dict[object, Connection],
        total: int,
        callbacks: ScanJobCallbacks,
    ) -> None:
        for completed, future in enumerate(as_completed(futures), start=1):
            if self._cancelled():
                break
            if self._handle_future_result(future, callbacks):
                break
            if callbacks.on_progress:
                callbacks.on_progress(completed, total)
            if self._cancelled():
                break
            self._close_single_log_channel(log_channels.pop(future, None))
        self._close_remaining_channels(log_channels)

    def _handle_future_result(self, future, callbacks: ScanJobCallbacks) -> bool:
        try:
            result = future.result()
        except BrokenProcessPool as exc:
            if callbacks.on_error:
                callbacks.on_error(build_error(ERROR_WORKER_POOL_FAILED, detail=str(exc)))
            return True
        except Exception as exc:  # pragma: no cover - propagated errors are rare
            if callbacks.on_error:
                callbacks.on_error(build_error(ERROR_SCAN_CRASHED, detail=str(exc)))
            return False
        if callbacks.on_result:
            if isinstance(result, list):
                for item in result:
                    callbacks.on_result(item)
            else:
                callbacks.on_result(result)
        return False

    def _create_log_channel(
        self, log_consumer: Callable[[ScanLogEvent], None] | None
    ) -> Connection | None:
        if log_consumer is None:
            return None
        try:
            rx, tx = self._mp_context.Pipe(duplex=False)
        except (OSError, ValueError):
            return None
        thread = Thread(target=self._relay_log_events, args=(rx, log_consumer), daemon=True)
        thread.start()
        self._log_receivers.append(rx)
        self._log_threads.append(thread)
        return tx

    def _relay_log_events(self, connection: Connection, log_consumer) -> None:
        try:
            while True:
                try:
                    event = connection.recv()
                except (EOFError, OSError, ValueError):
                    break
                else:
                    log_consumer(event)
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

    def _close_remaining_channels(self, log_channels: dict[object, Connection]) -> None:
        for conn in log_channels.values():
            self._close_single_log_channel(conn)

    def _close_single_log_channel(self, connection: Connection | None) -> None:
        if connection is not None:
            with suppress(OSError):
                connection.close()

    def _init_cancel_token(self) -> None:
        tx, token = create_pipe_cancel_token(self._mp_context)
        self._cancel_tx = tx
        self._cancel_token = token

    def _close_cancel_token(self) -> None:
        if self._cancel_tx is not None:
            with suppress(OSError):
                self._cancel_tx.close()
        self._cancel_tx = None
        if self._cancel_token is not None:
            self._cancel_token.close()
        self._cancel_token = None

    def _cancelled(self) -> bool:
        return bool(self._cancel_token and self._cancel_token.is_set())


def _should_use_threads() -> bool:
    return os.name == "nt" or sys.platform == "darwin"


def _send_log_event(connection: Connection | None, event: ScanLogEvent) -> None:
    if connection is None:
        return
    with suppress(BrokenPipeError, OSError):
        connection.send(event)


__all__ = ["ScanJobCallbacks", "ScanJobExecutor"]
