import multiprocessing as mp
import time
from concurrent.futures import Future, ProcessPoolExecutor
from types import SimpleNamespace

import pytest

from nmap_gui import scan_manager
from nmap_gui.cancel_token import PipeCancelToken
from nmap_gui.error_codes import ERROR_SCAN_CRASHED, ERROR_WORKER_POOL_FAILED
from nmap_gui.models import ScanConfig, ScanMode

THREAD_WORKER_COUNT = 2
PROCESS_WORKER_COUNT = 3


def _worker(token: PipeCancelToken):
    while not token.is_set():
        # Busy-wait until cancellation is signaled; test only verifies token propagation.
        pass
    return True


def test_pipe_cancel_token_can_cross_spawn_boundary():
    ctx = mp.get_context("spawn")
    rx, tx = ctx.Pipe(duplex=False)
    token = PipeCancelToken(rx)
    with ProcessPoolExecutor(max_workers=1, mp_context=ctx) as executor:
        future = executor.submit(_worker, token)
        tx.send(True)
        assert future.result() is True
    rx.close()
    tx.close()


def test_should_use_threads_on_darwin(monkeypatch):
    monkeypatch.setattr(scan_manager, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(scan_manager, "sys", SimpleNamespace(platform="darwin"))
    assert scan_manager._should_use_threads() is True


def _make_worker_spies():
    config = ScanConfig(targets=["target"], scan_modes={ScanMode.ICMP})
    worker = scan_manager.ScanWorker(config)
    emitted: list[object] = []
    errors: list[object] = []
    progress: list[tuple[int, int]] = []
    worker.result_ready = SimpleNamespace(emit=lambda payload: emitted.append(payload))
    worker.error = SimpleNamespace(emit=lambda payload: errors.append(payload))
    worker.progress = SimpleNamespace(emit=lambda completed, total: progress.append((completed, total)))
    return worker, emitted, errors, progress


def test_consume_futures_emits_each_payload():
    worker, emitted, errors, progress = _make_worker_spies()
    future = Future()
    payloads = ["a", "b"]
    future.set_result(payloads)
    worker._consume_futures({future: "target"}, {}, total=1)
    assert emitted == payloads
    assert errors == []
    assert progress == [(1, 1)]


def test_consume_futures_handles_broken_process_pool():
    worker, emitted, errors, _ = _make_worker_spies()
    closed = []
    worker._close_single_log_channel = lambda conn: closed.append(conn)
    future = Future()
    future.set_exception(scan_manager.BrokenProcessPool("boom"))
    channel = object()
    worker._consume_futures({future: "target"}, {future: channel}, total=1)
    assert emitted == []
    assert errors
    assert closed == [channel]


def test_consume_futures_continues_after_generic_error():
    worker, emitted, errors, progress = _make_worker_spies()
    first = Future()
    first.set_exception(RuntimeError("network"))
    second = Future()
    second.set_result("ok")
    class DummyConn:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    channels = {first: DummyConn(), second: DummyConn()}
    worker._consume_futures({first: "a", second: "b"}, channels, total=2)
    assert errors
    assert emitted == ["ok"]
    assert progress[-1] == (2, 2)


def test_prepare_targets_deduplicates_order():
    config = ScanConfig(targets=["a", "b", "a", "c"], scan_modes={ScanMode.ICMP})
    worker = scan_manager.ScanWorker(config)
    assert worker._prepare_targets() == ["a", "b", "c"]


def test_executor_config_respects_parallel_limits():
    config = ScanConfig(targets=["a"], scan_modes={ScanMode.ICMP}, max_parallel=5)
    worker = scan_manager.ScanWorker(config)
    worker._use_threads = True
    executor_cls, kwargs = worker._executor_config(total=THREAD_WORKER_COUNT)
    assert executor_cls is scan_manager.ThreadPoolExecutor
    assert kwargs["max_workers"] == THREAD_WORKER_COUNT


def test_executor_config_includes_mp_context_when_using_processes():
    config = ScanConfig(targets=["a", "b"], scan_modes={ScanMode.ICMP}, max_parallel=10)
    worker = scan_manager.ScanWorker(config)
    worker._use_threads = False
    executor_cls, kwargs = worker._executor_config(total=PROCESS_WORKER_COUNT)
    assert executor_cls is ProcessPoolExecutor
    assert kwargs["max_workers"] == PROCESS_WORKER_COUNT
    assert "mp_context" in kwargs


def test_emit_result_payload_iterates_lists():
    worker, emitted, _, _ = _make_worker_spies()
    worker._emit_result_payload(["one", "two"])
    assert emitted == ["one", "two"]


def test_handle_future_result_emits_worker_pool_error():
    worker, _, errors, _ = _make_worker_spies()
    future = Future()
    future.set_exception(scan_manager.BrokenProcessPool("boom"))

    should_stop = worker._handle_future_result(future)

    assert should_stop is True
    assert errors and errors[0].code == ERROR_WORKER_POOL_FAILED.code


def test_handle_future_result_reports_generic_crash():
    worker, _, errors, _ = _make_worker_spies()
    future = Future()
    future.set_exception(RuntimeError("boom"))

    should_stop = worker._handle_future_result(future)

    assert should_stop is False
    assert errors and errors[0].code == ERROR_SCAN_CRASHED.code


def test_handle_future_result_emits_normal_payload():
    worker, emitted, errors, _ = _make_worker_spies()
    future = Future()
    future.set_result("ok")

    should_stop = worker._handle_future_result(future)

    assert should_stop is False
    assert emitted == ["ok"]
    assert errors == []


def test_create_log_channel_relays_events():
    worker, _, _, _ = _make_worker_spies()
    logs: list[object] = []
    worker.log_ready = SimpleNamespace(emit=lambda payload: logs.append(payload))

    channel = worker._create_log_channel()
    assert channel is not None
    channel.send("ping")
    channel.close()
    time.sleep(0.05)
    worker._close_log_receivers()
    assert logs == ["ping"]


def test_close_remaining_channels_closes_all():
    worker, *_ = _make_worker_spies()

    class DummyConn:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    conns = {object(): DummyConn(), object(): DummyConn()}
    worker._close_remaining_channels(conns)
    assert all(conn.closed for conn in conns.values())


def test_cancelled_respects_token_state():
    worker, *_ = _make_worker_spies()

    class DummyToken:
        def __init__(self, flag: bool):
            self._flag = flag

        def is_set(self):
            return self._flag

    worker._cancel_token = DummyToken(True)
    assert worker._cancelled() is True
    worker._cancel_token = DummyToken(False)
    assert worker._cancelled() is False


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


def test_send_log_event_sends_payload():
    class DummyConn:
        def __init__(self):
            self.sent: list[object] = []

        def send(self, payload):
            self.sent.append(payload)

    conn = DummyConn()
    scan_manager._send_log_event(conn, "hello")
    assert conn.sent == ["hello"]


def test_send_log_event_swallows_broken_pipe():
    class DummyConn:
        def send(self, payload):
            raise BrokenPipeError("closed")

    scan_manager._send_log_event(DummyConn(), "ignored")


def test_send_log_event_returns_when_connection_missing():
    # Should safely return even when no pipe connection is provided.
    scan_manager._send_log_event(None, "ignored")


def test_scan_worker_start_handles_empty_target_list():
    config = ScanConfig(targets=[], scan_modes={ScanMode.ICMP})
    worker = scan_manager.ScanWorker(config)
    finished: list[str] = []
    worker.finished = SimpleNamespace(emit=lambda: finished.append("finished"))
    worker._close_cancel_token = lambda: finished.append("token_closed")

    worker.start()

    assert finished == ["finished", "token_closed"]


def test_scan_worker_start_runs_executor_path(monkeypatch):
    config = ScanConfig(targets=["alpha"], scan_modes={ScanMode.ICMP})
    worker = scan_manager.ScanWorker(config)
    events: list[str] = []
    worker.finished = SimpleNamespace(emit=lambda: events.append("finished"))
    worker._close_cancel_token = lambda: events.append("token_closed")
    worker._close_log_receivers = lambda: events.append("logs_closed")
    worker._prepare_targets = lambda: ["alpha"]

    class DummyExecutor:
        def __init__(self, **kwargs):
            events.append(f"executor_init:{kwargs['max_workers']}")

        def __enter__(self):
            events.append("executor_enter")
            return self

        def __exit__(self, exc_type, exc, tb):
            events.append("executor_exit")
            return False

    def fake_executor_config(total):
        events.append(f"config_total:{total}")
        return DummyExecutor, {"max_workers": 1}

    def fake_submit_targets(executor, targets):
        events.append(f"targets:{targets}")
        return ({object(): "alpha"}, {})

    def fake_consume(futures, log_channels, total):
        events.append(f"consume:{total}")

    worker._executor_config = fake_executor_config
    worker._submit_targets = fake_submit_targets
    worker._consume_futures = fake_consume

    worker.start()

    assert events.count("finished") == 1
    assert events[-2:] == ["token_closed", "logs_closed"]


def test_close_cancel_token_closes_resources():
    config = ScanConfig(targets=["a"], scan_modes={ScanMode.ICMP})
    worker = scan_manager.ScanWorker(config)

    class DummyConn:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    tx = DummyConn()
    token = DummyConn()
    worker._cancel_tx = tx
    worker._cancel_token = token

    worker._close_cancel_token()

    assert tx.closed and token.closed
    assert worker._cancel_tx is None and worker._cancel_token is None


def test_submit_targets_registers_log_channels(monkeypatch):
    config = ScanConfig(targets=["a"], scan_modes={ScanMode.ICMP})
    worker = scan_manager.ScanWorker(config)

    class DummyConn:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    def fake_create_channel():
        return DummyConn()

    worker._create_log_channel = fake_create_channel

    class DummyExecutor:
        def submit(self, func, *args):
            self.called_with = args
            return object()

    futures, channels = worker._submit_targets(DummyExecutor(), ["host"])

    assert len(futures) == 1
    assert len(channels) == 1
    future = next(iter(futures))
    assert channels[future] is not None


def test_submit_targets_closes_channel_on_submit_error(monkeypatch):
    config = ScanConfig(targets=["a"], scan_modes={ScanMode.ICMP})
    worker = scan_manager.ScanWorker(config)

    class DummyConn:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    dummy_conn = DummyConn()
    worker._create_log_channel = lambda: dummy_conn

    class FailingExecutor:
        def submit(self, *args, **kwargs):
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        worker._submit_targets(FailingExecutor(), ["host"])
    assert dummy_conn.closed is True


def test_consume_futures_stops_when_cancelled():
    worker, emitted, _, _ = _make_worker_spies()

    future = Future()
    future.set_result("ignored")

    worker._cancelled = lambda: True

    worker._consume_futures({future: "target"}, {}, total=1)

    assert emitted == []


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


def test_scan_manager_start_and_stop(monkeypatch):
    monkeypatch.setattr(scan_manager, "QThread", _TrackingThread)
    created_workers: list[_ScanWorkerStub] = []

    def fake_worker(config, settings):
        worker = _ScanWorkerStub(config, settings)
        created_workers.append(worker)
        return worker

    monkeypatch.setattr(scan_manager, "ScanWorker", fake_worker)

    manager = scan_manager.ScanManager(settings=SimpleNamespace())
    manager.started = _fake_signal()
    started_counts: list[int] = []
    manager.started.connect(lambda count: started_counts.append(count))

    config = ScanConfig(targets=["x", "y"], scan_modes={ScanMode.ICMP})
    manager.start(config)

    assert started_counts == [2]
    assert isinstance(manager._thread, _TrackingThread)
    assert created_workers and isinstance(created_workers[0], _ScanWorkerStub)

    manager.stop()

    assert manager._worker is None
    assert manager._thread is None


def test_safe_script_manager_start_respects_unique_targets(monkeypatch):
    monkeypatch.setattr(scan_manager, "QThread", _TrackingThread)
    created_workers: list[_SafeScriptWorkerStub] = []

    def fake_worker(targets, settings):
        worker = _SafeScriptWorkerStub(targets, settings)
        created_workers.append(worker)
        return worker

    monkeypatch.setattr(scan_manager, "SafeScriptWorker", fake_worker)

    manager = scan_manager.SafeScriptManager(settings=SimpleNamespace())
    manager.started = _fake_signal()
    started_counts: list[int] = []
    manager.started.connect(lambda count: started_counts.append(count))

    manager.start(["a", "a", "b"])

    assert started_counts == [2]
    assert isinstance(manager._thread, _TrackingThread)
    assert created_workers and created_workers[0].start_called is True

    manager.stop()
    assert manager._thread is None


def test_safe_script_manager_start_ignores_running_instance(monkeypatch):
    class FakeThread:
        def __init__(self):
            self.started = _fake_signal()
            self.finished = _fake_signal()
            self.running = True

        def start(self):
            pass

        def isRunning(self):
            return self.running

        def quit(self):
            self.running = False

        def wait(self, timeout):
            pass

        def deleteLater(self):
            pass

    monkeypatch.setattr(scan_manager, "QThread", lambda: FakeThread())
    monkeypatch.setattr(scan_manager, "SafeScriptWorker", lambda targets, settings: SimpleNamespace(
        moveToThread=lambda thread: None,
        result_ready=_fake_signal(),
        error=_fake_signal(),
        progress=_fake_signal(),
        finished=_fake_signal(),
        start=lambda: None,
    ))

    manager = scan_manager.SafeScriptManager(settings=SimpleNamespace())
    manager._thread = FakeThread()
    manager._worker = SimpleNamespace()

    manager.start(["a"])

    assert isinstance(manager._worker, SimpleNamespace)
