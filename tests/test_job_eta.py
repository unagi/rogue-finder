"""Tests for the shared job ETA controller."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication

from nmap_gui import job_eta
from nmap_gui.job_eta import JobEtaController

EXPECTED_SECONDS = 5.0


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])
    return app


def test_job_eta_controller_emits_status_and_stops(qt_app, monkeypatch):
    statuses: list[str] = []
    summaries: list[str] = []
    controller = JobEtaController(qt_app, statuses.append, summaries.append)

    clock = {"value": 1000.0}

    def fake_monotonic() -> float:
        return clock["value"]

    monkeypatch.setattr(job_eta, "time", SimpleNamespace(monotonic=fake_monotonic))

    def build_message(remaining: float) -> str:
        return f"ETA {round(remaining)}s"

    controller.start(kind="fast", expected_seconds=EXPECTED_SECONDS, message_builder=build_message)
    assert controller.remaining_seconds() == EXPECTED_SECONDS

    clock["value"] += 3.0
    controller.refresh()

    clock["value"] += 4.0
    controller._on_tick()

    assert controller.remaining_seconds() is None
    assert statuses
    assert summaries


def test_job_eta_controller_restarts_for_new_kind(qt_app):
    statuses: list[str] = []
    controller = JobEtaController(qt_app, statuses.append)

    controller.start(kind="fast", expected_seconds=0.0, message_builder=lambda _: "fast")
    assert controller._timer.isActive() is False

    controller.start(kind="safe", expected_seconds=2.0, message_builder=lambda _: "safe")
    assert controller._timer.isActive() is True

    controller.stop("safe")
    assert controller._timer.isActive() is False
