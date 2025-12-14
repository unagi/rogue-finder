from types import SimpleNamespace

from nmap_gui import privileged_runner
from nmap_gui.infrastructure.config import get_settings
from nmap_gui.models import (
    HostScanResult,
    ScanConfig,
    ScanLogEvent,
    ScanMode,
    serialize_scan_config,
)
from nmap_gui.privileged_runner import (
    PrivilegedRunnerBackend,
    PrivilegedRunnerServer,
    _generate_pipe_endpoint,
    run_privileged_runner,
)

NON_WINDOWS_EXIT_CODE = 2
AUTH_KEY_LENGTH_BYTES = 32


class _DummyCallbacks:
    def __init__(self):
        self.errors = []
        self.finished = False

    def on_progress(self, *args, **kwargs):
        return None

    def on_result(self, *args, **kwargs):
        return None

    def on_error(self, error):
        self.errors.append(error)

    def on_finished(self):
        self.finished = True

    def on_log(self, *args, **kwargs):
        return None


def test_privileged_runner_backend_handles_failed_connection(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    monkeypatch.setattr(
        privileged_runner.PrivilegedRunnerBackend,
        "_ensure_connection",
        lambda self: False,
    )
    callbacks = _DummyCallbacks()
    config = ScanConfig(targets=["alpha"], scan_modes={ScanMode.ICMP})

    backend.start(config, callbacks)

    assert callbacks.errors and callbacks.finished
    assert backend.is_running() is False


def test_privileged_runner_backend_start_and_stop(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())

    def fake_ensure(self):
        self._connection = object()
        return True

    sent: list[dict[str, object]] = []

    def fake_send(self, payload):
        sent.append(payload)

    monkeypatch.setattr(
        privileged_runner.PrivilegedRunnerBackend,
        "_ensure_connection",
        fake_ensure,
    )
    monkeypatch.setattr(
        privileged_runner.PrivilegedRunnerBackend,
        "_send",
        fake_send,
    )

    config = ScanConfig(targets=["alpha"], scan_modes={ScanMode.ICMP})
    callbacks = _DummyCallbacks()

    backend.start(config, callbacks)
    assert backend.is_running() is True
    assert sent[0]["type"] == "start_scan"

    backend.stop()
    assert backend.is_running() is False
    assert sent[1]["type"] == "stop_scan"


def test_privileged_runner_backend_dispatches_messages(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    callbacks = SimpleNamespace(
        progress=[],
        results=[],
        logs=[],
        errors=[],
        finished=False,
        on_progress=lambda done, total: callbacks.progress.append((done, total)),
        on_result=lambda result: callbacks.results.append(result),
        on_log=lambda event: callbacks.logs.append(event),
        on_error=lambda error: callbacks.errors.append(error),
        on_finished=lambda: setattr(callbacks, "finished", True),
    )
    backend._callbacks = callbacks  # type: ignore[attr-defined]
    backend._scan_active = True

    backend._dispatch_message({"type": "progress", "completed": 1, "total": 2})
    backend._dispatch_message({"type": "result", "result": {"target": "alpha"}})
    backend._dispatch_message({"type": "log", "event": {"target": "alpha", "stream": "stdout", "line": "msg"}})
    backend._dispatch_message({"type": "error", "error": {"code": "RF999", "message_key": "k", "action_key": "a"}})
    backend._dispatch_message({"type": "finished"})

    assert callbacks.progress == [(1, 2)]
    assert [result.target for result in callbacks.results] == ["alpha"]
    assert [event.line for event in callbacks.logs] == ["msg"]
    assert callbacks.errors and callbacks.finished
    assert backend.is_running() is False


def test_privileged_runner_backend_handle_runner_lost(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    backend._connection = object()  # type: ignore[assignment]
    backend._scan_active = True
    callbacks = _DummyCallbacks()
    backend._callbacks = callbacks  # type: ignore[attr-defined]

    backend._handle_runner_lost()

    assert callbacks.errors and callbacks.finished
    assert backend._connection is None
    assert backend.is_running() is False


def test_privileged_runner_server_handles_messages(monkeypatch):
    sent: list[dict[str, object]] = []

    class DummyConnection:
        def send(self, payload):
            sent.append(payload)

        def recv(self):
            raise EOFError

    class FakeExecutor:
        def __init__(self, settings=None):
            self.settings = settings
            self.cancel_called = False

        def run(self, config, callbacks):
            callbacks.on_progress(1, len(config.targets))
            callbacks.on_result(HostScanResult(target="alpha"))
            callbacks.on_log(ScanLogEvent(target="alpha", phase=None, stream="stdout", line="log"))

        def cancel(self):
            self.cancel_called = True

    class ImmediateThread:
        def __init__(self, target, args=(), daemon=True):
            self._target = target
            self._args = args

        def start(self):
            self._target(*self._args)

    monkeypatch.setattr(privileged_runner, "ScanJobExecutor", FakeExecutor)
    monkeypatch.setattr(privileged_runner.threading, "Thread", ImmediateThread)

    server = PrivilegedRunnerServer(DummyConnection())
    config = ScanConfig(targets=["alpha"], scan_modes={ScanMode.ICMP})
    message = {
        "type": "start_scan",
        "scan_id": "scan-1",
        "config": serialize_scan_config(config),
    }

    server._handle_message(message)
    assert any(payload["type"] == "progress" for payload in sent)
    assert any(payload["type"] == "result" for payload in sent)
    assert any(payload["type"] == "log" for payload in sent)
    assert any(payload["type"] == "finished" for payload in sent)

    server._executor = FakeExecutor()
    server._handle_message({"type": "stop_scan"})
    assert server._executor.cancel_called is True

    server._handle_message({"type": "shutdown"})
    assert server._stop_event.is_set()


def test_run_privileged_runner_non_windows(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "linux")
    assert run_privileged_runner("pipe", "00") == NON_WINDOWS_EXIT_CODE


def test_generate_pipe_endpoint_unique_format():
    name_a, key_a = _generate_pipe_endpoint()
    name_b, key_b = _generate_pipe_endpoint()

    normalized = name_a.replace("\\\\", "\\")
    assert normalized.startswith(r"\\.\pipe\rogue_finder_")
    assert name_a != name_b
    assert len(key_a) == AUTH_KEY_LENGTH_BYTES
    assert key_a != key_b
