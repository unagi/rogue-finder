"""Shared ETA controller for long-running GUI jobs."""
from __future__ import annotations

import time
from collections.abc import Callable

from PySide6.QtCore import QObject, QTimer


class JobEtaController(QObject):
    """Keeps status/summary text in sync for a long-running job."""

    def __init__(
        self,
        parent: QObject,
        status_callback: Callable[[str], None],
        summary_callback: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._status_callback = status_callback
        self._summary_callback = summary_callback
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._on_tick)
        self._kind: str | None = None
        self._message_builder: Callable[[float], str] | None = None
        self._started_at: float | None = None
        self._expected_seconds = 0.0

    def start(
        self,
        *,
        kind: str,
        expected_seconds: float,
        message_builder: Callable[[float], str],
    ) -> None:
        if self._kind and self._kind != kind:
            self.stop()
        self._kind = kind
        self._message_builder = message_builder
        self._started_at = time.monotonic()
        self._expected_seconds = max(expected_seconds, 0.0)
        self._emit_message(self._expected_seconds)
        if self._expected_seconds <= 0:
            return
        if not self._timer.isActive():
            self._timer.start()

    def refresh(self, kind: str | None = None) -> None:
        if self._kind is None or (kind and self._kind != kind):
            return
        remaining = self.remaining_seconds()
        if remaining is None:
            return
        self._emit_message(remaining)

    def stop(self, kind: str | None = None) -> None:
        if kind and self._kind != kind:
            return
        if self._timer.isActive():
            self._timer.stop()
        self._kind = None
        self._message_builder = None
        self._started_at = None
        self._expected_seconds = 0.0

    def remaining_seconds(self) -> float | None:
        if self._started_at is None:
            return None
        return max(self._expected_seconds - (time.monotonic() - self._started_at), 0.0)

    def _on_tick(self) -> None:
        if self._kind is None:
            self.stop()
            return
        remaining = self.remaining_seconds()
        if remaining is None:
            self.stop()
            return
        self._emit_message(remaining)
        if remaining <= 0:
            self.stop()

    def _emit_message(self, remaining: float) -> None:
        if not self._message_builder:
            return
        message = self._message_builder(max(remaining, 0.0))
        if not message:
            return
        self._status_callback(message)
        if self._summary_callback:
            self._summary_callback(message)
