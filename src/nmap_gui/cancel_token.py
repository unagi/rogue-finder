"""Inter-process cancellation primitives that avoid Qt dependencies."""
from __future__ import annotations

from contextlib import suppress
from multiprocessing.connection import Connection


class PipeCancelToken:
    """Lightweight cancellation token using the read side of a Pipe."""

    def __init__(self, connection: Connection):
        self._connection = connection

    def is_set(self) -> bool:
        try:
            return self._connection.poll()
        except (OSError, ValueError):
            # If the pipe endpoint is closed or broken assume cancellation.
            return True

    def close(self) -> None:
        with suppress(OSError):
            self._connection.close()


def create_pipe_cancel_token(context) -> tuple[Connection, PipeCancelToken]:
    """Return (writer_conn, cancel_token) pair for the provided context."""

    rx, tx = context.Pipe(duplex=False)
    return tx, PipeCancelToken(rx)
