"""Tests for the multiprocessing cancel token helpers."""
from __future__ import annotations

import multiprocessing as mp

from nmap_gui.cancel_token import PipeCancelToken, create_pipe_cancel_token


def test_pipe_cancel_token_reflects_pipe_activity():
    context = mp.get_context("spawn")
    writer, token = create_pipe_cancel_token(context)
    try:
        assert token.is_set() is False
        writer.send(None)
        assert token.is_set() is True
    finally:
        writer.close()
        token.close()


def test_pipe_cancel_token_handles_poll_errors():
    class BrokenConnection:
        def poll(self):  # pragma: no cover - invoked via token.is_set
            raise ValueError("poll failed")

        def close(self):
            pass

    token = PipeCancelToken(BrokenConnection())
    assert token.is_set() is True


def test_pipe_cancel_token_close_swallows_oserror():
    class NoisyConnection:
        def poll(self):
            return False

        def close(self):  # pragma: no cover - relies on suppress
            raise OSError("closed")

    token = PipeCancelToken(NoisyConnection())
    token.close()  # should not raise


def test_create_pipe_cancel_token_returns_duplex_pair():
    context = mp.get_context("spawn")
    writer, token = create_pipe_cancel_token(context)
    try:
        writer.send("data")
        assert token.is_set() is True
    finally:
        writer.close()
        token.close()
