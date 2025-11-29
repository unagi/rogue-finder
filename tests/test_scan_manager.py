import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor

from types import SimpleNamespace

import pytest

from nmap_gui.cancel_token import PipeCancelToken
from nmap_gui import scan_manager


def _worker(token: PipeCancelToken):
    while not token.is_set():
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
