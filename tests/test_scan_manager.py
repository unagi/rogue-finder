from types import SimpleNamespace

from nmap_gui import scan_controller, scan_manager
from nmap_gui.models import ScanConfig, ScanMode


def _fake_signal():
    class SignalStub:
        def __init__(self):
            self.handlers = []

        def connect(self, handler):
            self.handlers.append(handler)

        def emit(self, *args, **kwargs):
            for handler in list(self.handlers):
                handler(*args, **kwargs)

    return SignalStub()


class _TrackingThread:
    def __init__(self):
        self.started = _fake_signal()
        self.finished = _fake_signal()
        self.running = False
        self.deleted = False

    def start(self):
        self.running = True
        for handler in list(self.started.handlers):
            handler()

    def isRunning(self):
        return self.running

    def quit(self):
        self.running = False

    def wait(self, timeout):
        for handler in list(self.finished.handlers):
            handler()

    def deleteLater(self):
        self.deleted = True


class _ScanWorkerStub:
    def __init__(self, config, settings):
        self.config = config
        self.settings = settings
        self.progress = _fake_signal()
        self.result_ready = _fake_signal()
        self.error = _fake_signal()
        self.log_ready = _fake_signal()
        self.finished = _fake_signal()
        self.thread = None
        self.stopped = False

    def moveToThread(self, thread):
        self.thread = thread

    def start(self):
        pass

    def request_stop(self):
        self.stopped = True


class _BackendStub:
    def __init__(self):
        self.running = False
        self.started_configs: list[ScanConfig] = []
        self.callbacks: scan_manager.ScanCallbacks | None = None
        self.settings = None

    def start(self, config, callbacks):
        self.running = True
        self.started_configs.append(config)
        self.callbacks = callbacks

    def stop(self):
        self.running = False

    def is_running(self):
        return self.running

    def update_settings(self, settings):
        self.settings = settings


class _SafeBackendStub:
    def __init__(self):
        self.running = False
        self.started_targets: list[list[str]] = []
        self.callbacks: scan_manager.SafeScriptCallbacks | None = None
        self.settings = None

    def start(self, targets, callbacks):
        self.running = True
        self.started_targets.append(list(targets))
        self.callbacks = callbacks

    def stop(self):
        self.running = False

    def is_running(self):
        return self.running

    def update_settings(self, settings):
        self.settings = settings


class _SafeScriptWorkerStub:
    def __init__(self, targets, settings):
        self.targets = targets
        self.settings = settings
        self.start_called = False
        self.result_ready = _fake_signal()
        self.error = _fake_signal()
        self.progress = _fake_signal()
        self.finished = _fake_signal()
        self.thread = None

    def moveToThread(self, thread):
        self.thread = thread

    def start(self):
        self.start_called = True


def test_scan_worker_relays_executor_callbacks(monkeypatch):
    events: list[str] = []

    class DummyExecutor:
        def __init__(self, settings):
            self.settings = settings
            self.cancel_called = False

        def run(self, config, callbacks):
            callbacks.on_progress(1, 3)
            callbacks.on_result("payload")
            callbacks.on_error("error")
            callbacks.on_log("log-line")

        def cancel(self):
            self.cancel_called = True

    monkeypatch.setattr(scan_manager, "ScanJobExecutor", DummyExecutor)

    config = ScanConfig(targets=["host"], scan_modes={ScanMode.ICMP})
    worker = scan_manager.ScanWorker(config)
    worker.progress = SimpleNamespace(emit=lambda done, total: events.append(f"progress:{done}/{total}"))
    worker.result_ready = SimpleNamespace(emit=lambda payload: events.append(f"result:{payload}"))
    worker.error = SimpleNamespace(emit=lambda payload: events.append(f"error:{payload}"))
    worker.log_ready = SimpleNamespace(emit=lambda payload: events.append(f"log:{payload}"))
    worker.finished = SimpleNamespace(emit=lambda: events.append("finished"))

    worker.start()

    assert events == [
        "progress:1/3",
        "result:payload",
        "error:error",
        "log:log-line",
        "finished",
    ]


def test_scan_worker_request_stop_invokes_executor_cancel(monkeypatch):
    class DummyExecutor:
        def __init__(self, settings):
            self.cancel_called = False

        def run(self, config, callbacks):
            pass

        def cancel(self):
            self.cancel_called = True

    dummy_executor = DummyExecutor(None)

    def factory(settings):
        return dummy_executor

    monkeypatch.setattr(scan_manager, "ScanJobExecutor", factory)

    worker = scan_manager.ScanWorker(ScanConfig(targets=["a"], scan_modes={ScanMode.ICMP}))
    worker.request_stop()
    assert dummy_executor.cancel_called is True


def test_direct_scan_backend_uses_worker_thread(monkeypatch):
    monkeypatch.setattr(scan_manager, "QThread", _TrackingThread)
    created_workers: list[_ScanWorkerStub] = []

    def fake_worker(config, settings):
        worker = _ScanWorkerStub(config, settings)
        created_workers.append(worker)
        return worker

    monkeypatch.setattr(scan_manager, "ScanWorker", fake_worker)

    backend = scan_manager.DirectScanBackend(settings=SimpleNamespace())
    callbacks = scan_manager.ScanCallbacks(
        on_started=lambda total: None,
        on_progress=lambda done, total: None,
        on_result=lambda payload: None,
        on_error=lambda payload: None,
        on_finished=lambda: None,
        on_log=lambda event: None,
    )

    config = ScanConfig(targets=["x", "y"], scan_modes={ScanMode.ICMP})
    backend.start(config, callbacks)

    assert backend.is_running() is True
    assert created_workers and isinstance(created_workers[0], _ScanWorkerStub)
    assert isinstance(created_workers[0].thread, _TrackingThread)

    backend.stop()
    assert backend.is_running() is False


def test_direct_scan_backend_forwards_worker_signals(monkeypatch):
    monkeypatch.setattr(scan_manager, "QThread", _TrackingThread)

    class FiringWorker(_ScanWorkerStub):
        def start(self):
            self.progress.emit(1, 3)
            self.result_ready.emit("payload")
            self.error.emit("boom")
            self.log_ready.emit("log-entry")

    monkeypatch.setattr(scan_manager, "ScanWorker", FiringWorker)

    backend = scan_manager.DirectScanBackend(settings=SimpleNamespace())
    collected: list[tuple[str, object]] = []
    logs: list[object] = []
    finished: list[str] = []

    callbacks = scan_manager.ScanCallbacks(
        on_started=lambda total: None,
        on_progress=lambda done, total: collected.append(("progress", (done, total))),
        on_result=lambda payload: collected.append(("result", payload)),
        on_error=lambda payload: collected.append(("error", payload)),
        on_finished=lambda: finished.append("done"),
        on_log=lambda event: logs.append(event),
    )

    backend.start(ScanConfig(targets=["alpha"], scan_modes={ScanMode.ICMP}), callbacks)
    assert collected == [
        ("progress", (1, 3)),
        ("result", "payload"),
        ("error", "boom"),
    ]
    assert logs == ["log-entry"]

    backend._worker.finished.emit()  # type: ignore[union-attr]
    assert finished == ["done"]

    backend.stop()
    assert backend.is_running() is False


def test_scan_manager_prefers_privileged_backend_when_available(monkeypatch):
    monkeypatch.setattr(scan_manager, "QThread", _TrackingThread)

    class DummyRunnerBackend:
        def __init__(self, settings):
            self.settings = settings
            self.started = []
            self.running = False
            self.closed = False

        def start(self, config, callbacks):
            self.started.append(config)
            self.running = True

        def stop(self):
            self.running = False

        def is_running(self):
            return self.running

        def update_settings(self, settings):
            self.settings = settings

        def close(self):
            self.closed = True

    monkeypatch.setattr(scan_manager, "_privileged_backend_available", lambda: True)
    monkeypatch.setattr(
        scan_manager,
        "_create_privileged_backend",
        lambda settings: DummyRunnerBackend(settings),
    )

    runtime = SimpleNamespace(windows_privileged_runner=True)
    settings = SimpleNamespace(runtime=runtime)
    manager = scan_manager.ScanManager(settings=settings)
    assert isinstance(manager._backend, scan_manager.PrivilegedScanBackend)  # type: ignore[attr-defined]

    config = ScanConfig(targets=["host"], scan_modes={ScanMode.ICMP})
    callbacks = scan_manager.ScanCallbacks(
        on_started=lambda total: None,
        on_progress=lambda done, total: None,
        on_result=lambda payload: None,
        on_error=lambda payload: None,
        on_finished=lambda: None,
        on_log=lambda event: None,
    )
    manager.start(config, callbacks)
    assert manager.is_running() is True
    manager.stop()
    assert manager.is_running() is False

    monkeypatch.setattr(scan_manager, "_privileged_backend_available", lambda: False)
    new_runtime = SimpleNamespace(windows_privileged_runner=False)
    new_settings = SimpleNamespace(runtime=new_runtime)
    manager.update_settings(new_settings)
    assert isinstance(manager._backend, scan_manager.DirectScanBackend)  # type: ignore[attr-defined]


def _dummy_settings():
    return SimpleNamespace(runtime=SimpleNamespace(windows_privileged_runner=False))


def test_scan_controller_propagates_callbacks():
    backend = _BackendStub()
    manager = scan_manager.ScanManager(settings=_dummy_settings(), backend=backend)
    controller = scan_controller.ScanController(manager=manager)
    controller.started = _fake_signal()
    controller.progress = _fake_signal()
    controller.result_ready = _fake_signal()
    controller.error = _fake_signal()
    controller.finished = _fake_signal()
    controller.log_ready = _fake_signal()

    started: list[int] = []
    controller.started.connect(started.append)

    config = ScanConfig(targets=["a", "b"], scan_modes={ScanMode.ICMP})
    controller.start(config)

    assert started == [2]
    assert backend.running is True
    assert backend.callbacks is not None

    progress: list[tuple[int, int]] = []
    controller.progress.connect(lambda done, total: progress.append((done, total)))
    backend.callbacks.on_progress(1, 2)  # type: ignore[union-attr]
    assert progress == [(1, 2)]

    results: list[object] = []
    controller.result_ready.connect(results.append)
    backend.callbacks.on_result("payload")  # type: ignore[union-attr]
    assert results == ["payload"]

    errors: list[object] = []
    controller.error.connect(errors.append)
    backend.callbacks.on_error("boom")  # type: ignore[union-attr]
    assert errors == ["boom"]

    logs: list[object] = []
    controller.log_ready.connect(logs.append)
    backend.callbacks.on_log("log-line")  # type: ignore[union-attr]
    assert logs == ["log-line"]

    finished: list[str] = []
    controller.finished.connect(lambda: finished.append("done"))
    backend.callbacks.on_finished()  # type: ignore[union-attr]
    assert finished == ["done"]

    assert controller.is_running() is True

    controller.stop()
    assert backend.running is False
    assert controller.is_running() is False

    sentinel_settings = _dummy_settings()
    controller.update_settings(sentinel_settings)
    assert backend.settings is sentinel_settings


def test_safe_script_worker_runs_targets(monkeypatch):
    settings = SimpleNamespace(
        safe_scan=SimpleNamespace(timeout_seconds=10, max_parallel=2)
    )
    worker = scan_manager.SafeScriptWorker(["t1", "t2", "t1"], settings)

    reports: list[str] = []
    errors: list[Exception] = []
    progress: list[tuple[int, int]] = []
    finished: list[str] = []
    worker.result_ready = SimpleNamespace(emit=lambda payload: reports.append(payload))
    worker.error = SimpleNamespace(emit=lambda exc: errors.append(exc))
    worker.progress = SimpleNamespace(emit=lambda done, total: progress.append((done, total)))
    worker.finished = SimpleNamespace(emit=lambda: finished.append("done"))

    class FakeFuture:
        def __init__(self, result=None, error: Exception | None = None):
            self._result = result
            self._error = error

        def result(self):
            if self._error:
                raise self._error
            return self._result

    futures_by_target = {
        "t1": FakeFuture(result="report"),
        "t2": FakeFuture(error=RuntimeError("boom")),
    }

    class FakeExecutor:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def submit(self, func, target, timeout, settings):
            return futures_by_target[target]

    monkeypatch.setattr(scan_manager, "ThreadPoolExecutor", lambda **kwargs: FakeExecutor(**kwargs))
    monkeypatch.setattr(scan_manager, "as_completed", lambda futures: list(futures))

    worker.start()

    assert reports == ["report"]
    assert errors and isinstance(errors[0], RuntimeError)
    assert progress[-1] == (2, 2)
    assert finished == ["done"]


def test_safe_script_worker_handles_no_targets():
    settings = SimpleNamespace(safe_scan=SimpleNamespace(timeout_seconds=5, max_parallel=1))
    worker = scan_manager.SafeScriptWorker([], settings)
    finished: list[str] = []
    worker.finished = SimpleNamespace(emit=lambda: finished.append("done"))

    worker.start()

    assert finished == ["done"]


def test_direct_safe_script_backend_runs_worker(monkeypatch):
    monkeypatch.setattr(scan_manager, "QThread", _TrackingThread)
    created_workers: list[_SafeScriptWorkerStub] = []

    def fake_worker(targets, settings):
        worker = _SafeScriptWorkerStub(targets, settings)
        created_workers.append(worker)
        return worker

    monkeypatch.setattr(scan_manager, "SafeScriptWorker", fake_worker)

    backend = scan_manager.DirectSafeScriptBackend(settings=SimpleNamespace())
    callbacks = scan_manager.SafeScriptCallbacks(
        on_started=lambda total: None,
        on_progress=lambda done, total: None,
        on_result=lambda payload: None,
        on_error=lambda payload: None,
        on_finished=lambda: None,
    )

    backend.start(["a", "b"], callbacks)

    assert created_workers and created_workers[0].targets == ["a", "b"]
    assert backend.is_running() is True

    backend.stop()
    assert backend.is_running() is False


def test_direct_safe_script_backend_forwards_signals(monkeypatch):
    monkeypatch.setattr(scan_manager, "QThread", _TrackingThread)

    class FiringSafeWorker(_SafeScriptWorkerStub):
        def start(self):
            self.progress.emit(1, 2)
            self.result_ready.emit("report")
            self.error.emit(RuntimeError("err"))

    monkeypatch.setattr(scan_manager, "SafeScriptWorker", FiringSafeWorker)

    backend = scan_manager.DirectSafeScriptBackend(settings=SimpleNamespace())
    progress: list[tuple[int, int]] = []
    results: list[object] = []
    errors: list[object] = []
    finished: list[str] = []

    callbacks = scan_manager.SafeScriptCallbacks(
        on_started=lambda total: None,
        on_progress=lambda done, total: progress.append((done, total)),
        on_result=lambda payload: results.append(payload),
        on_error=lambda payload: errors.append(payload),
        on_finished=lambda: finished.append("done"),
    )

    backend.start(["a"], callbacks)
    assert progress == [(1, 2)]
    assert results == ["report"]
    assert errors and isinstance(errors[0], RuntimeError)

    backend._worker.finished.emit()  # type: ignore[union-attr]
    assert finished == ["done"]

    backend.stop()
    assert backend.is_running() is False


def test_safe_script_controller_handles_unique_targets():
    backend = _SafeBackendStub()
    manager = scan_manager.SafeScriptManager(settings=_dummy_settings(), backend=backend)
    controller = scan_controller.SafeScriptController(manager=manager)
    controller.started = _fake_signal()
    controller.progress = _fake_signal()
    controller.result_ready = _fake_signal()
    controller.error = _fake_signal()
    controller.finished = _fake_signal()

    started: list[int] = []
    controller.started.connect(started.append)

    controller.start(["a", "a", "b"])

    assert started == [2]
    assert backend.started_targets == [["a", "b"]]
    assert backend.callbacks is not None

    progress: list[tuple[int, int]] = []
    controller.progress.connect(lambda done, total: progress.append((done, total)))
    backend.callbacks.on_progress(1, 2)  # type: ignore[union-attr]
    assert progress == [(1, 2)]

    assert controller.is_running() is True

    controller.stop()
    assert backend.running is False
    assert controller.is_running() is False

    sentinel = SimpleNamespace()
    controller.update_settings(sentinel)
    assert backend.settings is sentinel
