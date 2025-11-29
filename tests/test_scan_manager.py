import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor

from nmap_gui.scan_manager import create_cancel_event


def _worker(event):
    # Touch the event inside the child process to ensure it is shareable.
    event.set()
    return event.is_set()


def test_create_cancel_event_is_shareable_with_spawn_processes():
    ctx = mp.get_context("spawn")
    manager, event = create_cancel_event(ctx)
    try:
        with ProcessPoolExecutor(max_workers=1, mp_context=ctx) as executor:
            assert executor.submit(_worker, event).result() is True
    finally:
        manager.shutdown()
