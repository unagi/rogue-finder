from types import SimpleNamespace
from typing import Any

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


class _ImmediateThread:
    def __init__(self, target, args=(), daemon=True):
        self._target = target
        self._args = args

    def start(self):
        self._target(*self._args)

    def join(self, timeout=None):
        return None


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


def test_privileged_runner_backend_ensure_connection(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")

    created_listeners: list[object] = []

    class FakeListener:
        def __init__(self, address, family, authkey):
            self.address = address
            self.family = family
            self.authkey = authkey
            self.closed = False
            created_listeners.append(self)

        def accept(self):
            return "connection"

        def close(self):
            self.closed = True

    backend = PrivilegedRunnerBackend(get_settings())
    monkeypatch.setattr(privileged_runner, "Listener", FakeListener)
    monkeypatch.setattr(privileged_runner.threading, "Thread", _ImmediateThread)
    monkeypatch.setattr(
        privileged_runner.PrivilegedRunnerBackend,
        "_launch_privileged_runner",
        lambda self: True,
    )
    monkeypatch.setattr(
        privileged_runner.PrivilegedRunnerBackend,
        "_accept_with_timeout",
        lambda self, listener: "connection",
    )
    monkeypatch.setattr(
        privileged_runner.PrivilegedRunnerBackend,
        "_listen_loop",
        lambda self: None,
    )

    assert backend._ensure_connection() is True
    assert backend._connection == "connection"

def test_privileged_runner_backend_ensure_connection_short_circuit(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    backend._connection = object()  # type: ignore[assignment]
    assert backend._ensure_connection() is True


def test_privileged_runner_backend_ensure_connection_launch_failure(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")

    class FakeListener:
        def close(self):
            self.closed = True

    backend = PrivilegedRunnerBackend(get_settings())
    monkeypatch.setattr(privileged_runner, "Listener", lambda **kwargs: FakeListener())
    monkeypatch.setattr(
        privileged_runner.PrivilegedRunnerBackend,
        "_launch_privileged_runner",
        lambda self: False,
    )

    assert backend._ensure_connection() is False


def test_privileged_runner_backend_ensure_connection_accept_timeout(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")

    class FakeListener:
        def close(self):
            self.closed = True

    backend = PrivilegedRunnerBackend(get_settings())
    monkeypatch.setattr(privileged_runner, "Listener", lambda **kwargs: FakeListener())
    monkeypatch.setattr(
        privileged_runner.PrivilegedRunnerBackend,
        "_launch_privileged_runner",
        lambda self: True,
    )
    monkeypatch.setattr(
        privileged_runner.PrivilegedRunnerBackend,
        "_accept_with_timeout",
        lambda self, listener: None,
    )

    assert backend._ensure_connection() is False


def test_privileged_runner_backend_accept_with_timeout(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    monkeypatch.setattr(privileged_runner.threading, "Thread", _ImmediateThread)

    class FakeListener:
        def __init__(self):
            self.closed = False

        def accept(self):
            return "pipe"

        def close(self):
            self.closed = True

    backend = PrivilegedRunnerBackend(get_settings())

    listener = FakeListener()
    connection = backend._accept_with_timeout(listener)
    assert connection == "pipe"
    assert listener.closed is True

    class FailingListener(FakeListener):
        def accept(self):
            raise OSError("fail")

    assert backend._accept_with_timeout(FailingListener()) is None


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


def test_privileged_runner_backend_dispatch_without_callbacks(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    backend._callbacks = None  # type: ignore[attr-defined]
    backend._dispatch_message({"type": "status", "detail": "ok"})
    backend._callbacks = SimpleNamespace(
        on_progress=lambda *args: None,
        on_result=lambda *args: None,
        on_log=lambda *args: None,
        on_error=lambda *args: None,
        on_finished=lambda: None,
    )
    backend._dispatch_message({"type": "status", "detail": "info"})


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


def test_privileged_runner_backend_update_and_close(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())

    class DummyConnection:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    backend._connection = DummyConnection()  # type: ignore[assignment]
    backend._listener = DummyConnection()  # type: ignore[assignment]
    new_settings = get_settings()

    backend.update_settings(new_settings)
    assert backend._settings is new_settings

    backend.close()
    assert backend._connection is None
    assert backend._listener is None


def test_privileged_runner_backend_listen_loop_handles_disconnect(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    events: list[str] = []

    class FakeConnection:
        def __init__(self):
            self.calls = 0

        def recv(self):
            if self.calls == 0:
                self.calls += 1
                return {"type": "status", "detail": "ok"}
            raise EOFError

    backend._connection = FakeConnection()  # type: ignore[assignment]
    backend._callbacks = SimpleNamespace(
        on_progress=lambda *args, **kwargs: events.append("progress"),
        on_result=lambda *args, **kwargs: events.append("result"),
        on_log=lambda *args, **kwargs: events.append("log"),
        on_error=lambda *args, **kwargs: events.append("error"),
        on_finished=lambda: events.append("finished"),
    )

    backend._listen_loop()
    assert events == ["error", "finished"]
    assert backend._connection is None


def test_privileged_runner_backend_send_handles_oserror(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())

    class FailingConnection:
        def send(self, payload):
            raise OSError("boom")

    backend._connection = FailingConnection()  # type: ignore[assignment]
    callbacks = _DummyCallbacks()
    backend._callbacks = callbacks  # type: ignore[attr-defined]

    backend._send({"type": "status"})
    assert callbacks.errors and callbacks.finished


def test_privileged_runner_backend_send_without_connection(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    backend._connection = None
    backend._send({"type": "status"})


def test_privileged_runner_backend_listen_loop_no_connection(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    backend._connection = None
    backend._shutdown = False
    backend._listen_loop()


def test_launch_privileged_runner_handles_shell_error(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    backend._pipe_name = "pipe"
    backend._auth_key = b"token"
    fake_shell = SimpleNamespace(ShellExecuteW=lambda *args: 10)
    monkeypatch.setattr(privileged_runner, "ctypes", SimpleNamespace(windll=SimpleNamespace(shell32=fake_shell)))

    assert backend._launch_privileged_runner() is False


def test_launch_privileged_runner_requires_state(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    backend._pipe_name = None
    backend._auth_key = None
    assert backend._launch_privileged_runner() is False


def test_launch_privileged_runner_success(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    backend = PrivilegedRunnerBackend(get_settings())
    backend._pipe_name = "pipe"
    backend._auth_key = b"token"
    fake_shell = SimpleNamespace(ShellExecuteW=lambda *args: 100)
    monkeypatch.setattr(privileged_runner, "ctypes", SimpleNamespace(windll=SimpleNamespace(shell32=fake_shell)))
    monkeypatch.setattr(privileged_runner.subprocess, "list2cmdline", lambda args: "cmd")

    assert backend._launch_privileged_runner() is True


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


def test_privileged_runner_server_run_executor_error(monkeypatch):
    sent: list[dict[str, object]] = []

    class DummyConnection:
        def send(self, payload):
            sent.append(payload)

    class FailingExecutor:
        def __init__(self, settings=None):
            pass

        def run(self, config, callbacks):
            raise RuntimeError("fail")

        def cancel(self):
            return None

    monkeypatch.setattr(privileged_runner, "ScanJobExecutor", FailingExecutor)
    monkeypatch.setattr(privileged_runner.threading, "Thread", _ImmediateThread)

    server = PrivilegedRunnerServer(DummyConnection())
    config = ScanConfig(targets=["alpha"], scan_modes={ScanMode.ICMP})
    server._handle_message(
        {
            "type": "start_scan",
            "scan_id": "scan-1",
            "config": serialize_scan_config(config),
        }
    )

    assert any(payload["type"] == "error" for payload in sent)
    assert any(payload["type"] == "finished" for payload in sent)


def test_privileged_runner_server_serve_forever(monkeypatch):
    messages = [{"type": "unknown"}]

    class FakeConnection:
        def recv(self):
            if messages:
                return messages.pop(0)
            raise EOFError

    server = PrivilegedRunnerServer(FakeConnection())  # type: ignore[arg-type]
    handled: list[dict[str, Any]] = []
    monkeypatch.setattr(server, "_handle_message", lambda message: handled.append(message))
    server.serve_forever()
    assert handled == [{"type": "unknown"}]


def test_privileged_runner_server_start_scan_busy():
    sent: list[dict[str, object]] = []
    server = PrivilegedRunnerServer(SimpleNamespace(send=lambda payload: sent.append(payload)))  # type: ignore[arg-type]
    server._executor = object()  # type: ignore[assignment]
    server._handle_message({"type": "start_scan"})
    assert any(payload["type"] == "status" for payload in sent)


def test_privileged_runner_server_cancel_scan_handles_none():
    server = PrivilegedRunnerServer(SimpleNamespace(send=lambda payload: None))  # type: ignore[arg-type]
    server._executor = None
    server._cancel_scan()
    class DummyExecutor:
        def __init__(self):
            self.cancelled = False

        def cancel(self):
            self.cancelled = True
    dummy = DummyExecutor()
    server._executor = dummy  # type: ignore[assignment]
    server._cancel_scan()
    assert dummy.cancelled is True


def test_privileged_runner_server_shutdown_executor():
    server = PrivilegedRunnerServer(SimpleNamespace(send=lambda payload: None))  # type: ignore[arg-type]
    class DummyExecutor:
        def __init__(self):
            self.cancelled = False

        def cancel(self):
            self.cancelled = True
    dummy = DummyExecutor()
    server._executor = dummy  # type: ignore[assignment]
    server._shutdown_executor()
    assert dummy.cancelled is True
    assert server._executor is None


def test_privileged_runner_server_handle_unknown_message():
    server = PrivilegedRunnerServer(SimpleNamespace(send=lambda payload: None))  # type: ignore[arg-type]
    server._handle_message({"type": "bogus"})


def test_run_privileged_runner_non_windows(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "linux")
    assert run_privileged_runner("pipe", "00") == NON_WINDOWS_EXIT_CODE


def test_run_privileged_runner_success(monkeypatch):
    monkeypatch.setattr(privileged_runner.sys, "platform", "win32")
    served = []

    class DummyServer:
        def __init__(self, connection):
            self.connection = connection

        def serve_forever(self):
            served.append(True)

    class DummyClient:
        def __init__(self, address, family, authkey):
            self.address = address
            self.family = family
            self.authkey = authkey

    monkeypatch.setattr(privileged_runner, "Client", lambda **kwargs: DummyClient(**kwargs))
    monkeypatch.setattr(privileged_runner, "PrivilegedRunnerServer", DummyServer)

    assert run_privileged_runner("pipe", "00") == 0
    assert served == [True]


def test_generate_pipe_endpoint_unique_format():
    name_a, key_a = _generate_pipe_endpoint()
    name_b, key_b = _generate_pipe_endpoint()

    normalized = name_a.replace("\\\\", "\\")
    assert normalized.startswith(r"\\.\pipe\rogue_finder_")
    assert name_a != name_b
    assert len(key_a) == AUTH_KEY_LENGTH_BYTES
    assert key_a != key_b


def test_suppress_broken_pipe_context():
    manager = privileged_runner.suppress_broken_pipe()
    assert manager.__exit__(BrokenPipeError, BrokenPipeError(), None) is True
