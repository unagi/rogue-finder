import multiprocessing as mp
from concurrent.futures import Future, ProcessPoolExecutor
from types import SimpleNamespace

from nmap_gui import scan_manager
from nmap_gui.cancel_token import PipeCancelToken
from nmap_gui.models import ScanConfig, ScanMode


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
