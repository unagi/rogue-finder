"""Privileged runner IPC plumbing for Windows builds."""
from __future__ import annotations

import ctypes
import logging
import os
import secrets
import subprocess
import sys
import threading
import uuid
from multiprocessing.connection import Client, Connection, Listener
from pathlib import Path
from typing import Any

from .errors import ERROR_SCAN_CRASHED, build_error
from .infrastructure.config import AppSettings, get_settings
from .models import (
    ErrorRecord,
    HostScanResult,
    ScanConfig,
    ScanLogEvent,
    deserialize_scan_config,
    serialize_scan_config,
)
from .scan_executor import ScanJobCallbacks, ScanJobExecutor

LOGGER = logging.getLogger(__name__)
PIPE_TIMEOUT_SECONDS = 15
SHELLEXECUTE_ERROR_THRESHOLD = 32


class PrivilegedRunnerBackend:
    """Scan backend that proxies discovery to a privileged runner process."""

    def __init__(self, settings: AppSettings) -> None:
        if sys.platform != "win32":  # pragma: no cover - guarded by caller
            raise RuntimeError("Privileged runner backend is only supported on Windows")
        self._settings = settings
        self._connection: Connection | None = None
        self._listener: Listener | None = None
        self._reader_thread: threading.Thread | None = None
        self._callbacks = None
        self._scan_id: str | None = None
        self._scan_active = False
        self._send_lock = threading.Lock()
        self._shutdown = False
        self._auth_key: bytes | None = None
        self._pipe_name: str | None = None

    def start(self, config: ScanConfig, callbacks) -> None:
        self.stop()
        self._callbacks = callbacks
        if not self._ensure_connection():
            callbacks.on_error(
                build_error(
                    ERROR_SCAN_CRASHED,
                    detail="Failed to launch privileged runner",
                )
            )
            callbacks.on_finished()
            return
        scan_id = str(uuid.uuid4())
        self._scan_id = scan_id
        self._scan_active = True
        self._send(
            {
                "type": "start_scan",
                "scan_id": scan_id,
                "config": serialize_scan_config(config),
            }
        )

    def stop(self) -> None:
        if self._scan_active and self._scan_id and self._connection is not None:
            self._send({"type": "stop_scan", "scan_id": self._scan_id})
        self._scan_active = False

    def is_running(self) -> bool:
        return self._scan_active

    def update_settings(self, settings: AppSettings) -> None:
        self._settings = settings

    def close(self) -> None:
        self._shutdown = True
        if self._connection is not None:
            with suppress_broken_pipe():
                self._connection.close()
        if self._listener is not None:
            self._listener.close()
        self._connection = None
        self._listener = None

    # ------------------------------------------------------------------
    def _ensure_connection(self) -> bool:
        if self._connection is not None:
            return True
        try:
            pipe_name, auth_key = _generate_pipe_endpoint()
            listener = Listener(address=pipe_name, family="AF_PIPE", authkey=auth_key)
        except OSError as exc:  # pragma: no cover - depends on OS state
            LOGGER.error("Failed to create privileged runner listener: %s", exc)
            return False
        self._listener = listener
        self._auth_key = auth_key
        self._pipe_name = pipe_name
        if not self._launch_privileged_runner():
            listener.close()
            self._listener = None
            return False
        connection = self._accept_with_timeout(listener)
        if connection is None:
            listener.close()
            self._listener = None
            LOGGER.error("Privileged runner did not connect within %s seconds", PIPE_TIMEOUT_SECONDS)
            return False
        self._connection = connection
        self._reader_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._reader_thread.start()
        return True

    def _launch_privileged_runner(self) -> bool:
        if self._pipe_name is None or self._auth_key is None:
            return False
        params = ["--mode", "runner", "--ipc-name", self._pipe_name, "--ipc-token", self._auth_key.hex()]
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            params.append("--debug")
        if getattr(sys, "frozen", False):
            executable = Path(sys.executable).resolve()
            arguments = subprocess.list2cmdline(params)
        else:
            executable = Path(sys.executable).resolve()
            arguments = subprocess.list2cmdline(["-m", "nmap_gui.main", *params])
        directory = str(Path.cwd())
        result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None,
            "runas",
            str(executable),
            arguments,
            directory,
            0,
        )
        if result <= SHELLEXECUTE_ERROR_THRESHOLD:
            LOGGER.error("ShellExecuteW failed with code %s", result)
            return False
        return True

    def _accept_with_timeout(self, listener: Listener) -> Connection | None:
        accepted: list[Connection] = []

        def _accept() -> None:
            try:
                conn = listener.accept()
            except OSError as exc:  # pragma: no cover - error path
                LOGGER.error("Privileged runner listener accept failed: %s", exc)
            else:
                accepted.append(conn)

        thread = threading.Thread(target=_accept, daemon=True)
        thread.start()
        thread.join(PIPE_TIMEOUT_SECONDS)
        if not accepted:
            listener.close()
            return None
        listener.close()
        return accepted[0]

    def _listen_loop(self) -> None:
        while not self._shutdown:
            if self._connection is None:
                break
            try:
                message = self._connection.recv()
            except EOFError:
                LOGGER.error("Privileged runner connection closed")
                self._handle_runner_lost()
                break
            except OSError as exc:  # pragma: no cover - OS-specific
                LOGGER.error("Privileged runner connection error: %s", exc)
                self._handle_runner_lost()
                break
            else:
                self._dispatch_message(message)

    def _dispatch_message(self, message: dict[str, Any]) -> None:
        msg_type = message.get("type")
        if not self._callbacks:
            return
        if msg_type == "progress":
            self._callbacks.on_progress(int(message.get("completed", 0)), int(message.get("total", 0)))
        elif msg_type == "result":
            payload = message.get("result") or {}
            self._callbacks.on_result(HostScanResult.from_dict(payload))
        elif msg_type == "log":
            event_payload = message.get("event") or {}
            self._callbacks.on_log(ScanLogEvent.from_message(event_payload))
        elif msg_type == "error":
            error_payload = message.get("error") or {}
            self._callbacks.on_error(ErrorRecord.from_dict(error_payload))
        elif msg_type == "finished":
            self._scan_active = False
            self._callbacks.on_finished()
        elif msg_type == "status":
            # informational; log for troubleshooting
            LOGGER.debug("Privileged runner status: %s", message.get("detail"))

    def _handle_runner_lost(self) -> None:
        self._connection = None
        self._scan_active = False
        if self._callbacks:
            self._callbacks.on_error(
                build_error(
                    ERROR_SCAN_CRASHED,
                    detail="Privileged runner disconnected",
                )
            )
            self._callbacks.on_finished()

    def _send(self, payload: dict[str, Any]) -> None:
        if self._connection is None:
            return
        with self._send_lock:
            try:
                self._connection.send(payload)
            except OSError as exc:  # pragma: no cover - depends on OS
                LOGGER.error("Failed to send message to privileged runner: %s", exc)
                self._handle_runner_lost()


class PrivilegedRunnerServer:
    """Runs inside the elevated runner process to execute scans."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection
        self._send_lock = threading.Lock()
        self._executor: ScanJobExecutor | None = None
        self._scan_thread: threading.Thread | None = None
        self._active_scan_id: str | None = None
        self._stop_event = threading.Event()

    def serve_forever(self) -> None:
        LOGGER.info("Privileged runner ready")
        while not self._stop_event.is_set():
            try:
                message = self._connection.recv()
            except EOFError:
                LOGGER.info("Parent disconnected; shutting down privileged runner")
                break
            self._handle_message(message)
        self._shutdown_executor()

    def _handle_message(self, message: dict[str, Any]) -> None:
        msg_type = message.get("type")
        if msg_type == "start_scan":
            self._start_scan(message)
        elif msg_type == "stop_scan":
            self._cancel_scan()
        elif msg_type == "shutdown":
            self._stop_event.set()
        else:
            LOGGER.debug("Unknown runner message: %s", msg_type)

    def _start_scan(self, message: dict[str, Any]) -> None:
        if self._executor is not None:
            self._send({"type": "status", "detail": "runner_busy"})
            return
        scan_id = str(message.get("scan_id"))
        config_payload = message.get("config") or {}
        config = deserialize_scan_config(config_payload)
        self._executor = ScanJobExecutor(settings=get_settings())
        self._active_scan_id = scan_id
        callbacks = ScanJobCallbacks(
            on_progress=lambda completed, total: self._send(
                {"type": "progress", "scan_id": scan_id, "completed": completed, "total": total}
            ),
            on_result=lambda result: self._send(
                {"type": "result", "scan_id": scan_id, "result": result.to_dict()}
            ),
            on_error=lambda error: self._send(
                {"type": "error", "scan_id": scan_id, "error": error.to_dict()}
            ),
            on_log=lambda event: self._send(
                {"type": "log", "scan_id": scan_id, "event": event.to_message()}
            ),
        )
        self._scan_thread = threading.Thread(
            target=self._run_executor,
            args=(self._executor, config, callbacks, scan_id),
            daemon=True,
        )
        self._scan_thread.start()

    def _cancel_scan(self) -> None:
        if self._executor is not None:
            self._executor.cancel()

    def _run_executor(
        self,
        executor: ScanJobExecutor,
        config: ScanConfig,
        callbacks: ScanJobCallbacks,
        scan_id: str,
    ) -> None:
        try:
            executor.run(config, callbacks)
        except Exception as exc:  # pragma: no cover - unexpected crash
            LOGGER.exception("Privileged runner scan crashed")
            self._send(
                {
                    "type": "error",
                    "scan_id": scan_id,
                    "error": build_error(ERROR_SCAN_CRASHED, detail=str(exc)).to_dict(),
                }
            )
        finally:
            self._send({"type": "finished", "scan_id": scan_id})
            self._executor = None
            self._active_scan_id = None

    def _shutdown_executor(self) -> None:
        if self._executor is not None:
            self._executor.cancel()
            self._executor = None

    def _send(self, payload: dict[str, Any]) -> None:
        with self._send_lock:
            try:
                self._connection.send(payload)
            except OSError as exc:  # pragma: no cover
                LOGGER.error("Failed to send runner payload: %s", exc)
                self._stop_event.set()


def run_privileged_runner(ipc_name: str, auth_token_hex: str) -> int:
    if sys.platform != "win32":  # pragma: no cover - only invoked on Windows
        LOGGER.error("Privileged runner mode is only available on Windows")
        return 2
    auth_key = bytes.fromhex(auth_token_hex)
    LOGGER.debug("Connecting privileged runner to %s", ipc_name)
    try:
        connection = Client(address=ipc_name, family="AF_PIPE", authkey=auth_key)
    except OSError as exc:  # pragma: no cover - depends on runtime
        LOGGER.error("Failed to connect to GUI privileged listener: %s", exc)
        return 1
    server = PrivilegedRunnerServer(connection)
    server.serve_forever()
    return 0


def _generate_pipe_endpoint() -> tuple[str, bytes]:
    suffix = secrets.token_hex(8)
    pipe_name = rf"\\\\.\pipe\\rogue_finder_{os.getpid()}_{suffix}"
    auth_key = secrets.token_bytes(32)
    return pipe_name, auth_key

class suppress_broken_pipe:
    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc, tb):
        return exc_type is BrokenPipeError
