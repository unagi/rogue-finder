import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor

from nmap_gui.scan_manager import PipeCancelToken


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
