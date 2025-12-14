"""Tests for the shared job ETA controller."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication

from nmap_gui import job_eta
from nmap_gui.job_eta import JobEtaController

EXPECTED_SECONDS = 5.0
EXPECTED_REFRESH_COUNT = 2


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


def test_job_eta_refresh_requires_matching_kind(qt_app, monkeypatch):
    statuses: list[str] = []
    controller = JobEtaController(qt_app, statuses.append)

    clock = {"value": 42.0}

    def fake_monotonic() -> float:
        return clock["value"]

    monkeypatch.setattr(job_eta, "time", SimpleNamespace(monotonic=fake_monotonic))

    controller.start(kind="fast", expected_seconds=10.0, message_builder=lambda r: f"{r:.1f}s")
    assert len(statuses) == 1

    clock["value"] += 2.0
    controller.refresh(kind="safe")
    assert len(statuses) == 1

    controller.refresh(kind="fast")
    assert len(statuses) == EXPECTED_REFRESH_COUNT


def test_job_eta_stop_ignores_mismatched_kind(qt_app, monkeypatch):
    statuses: list[str] = []
    controller = JobEtaController(qt_app, statuses.append)

    clock = {"value": 10.0}

    def fake_monotonic() -> float:
        return clock["value"]

    monkeypatch.setattr(job_eta, "time", SimpleNamespace(monotonic=fake_monotonic))

    controller.start(kind="safe", expected_seconds=3.0, message_builder=lambda r: f"safe {r:.0f}s")
    assert controller._timer.isActive() is True

    controller.stop(kind="fast")
    assert controller._timer.isActive() is True
    assert controller._kind == "safe"

    controller.stop("safe")
    assert controller._timer.isActive() is False
    assert controller.remaining_seconds() is None


def test_job_eta_skips_empty_messages(qt_app):
    statuses: list[str] = []
    summaries: list[str] = []
    controller = JobEtaController(qt_app, statuses.append, summaries.append)

    def builder(remaining: float) -> str:
        if remaining < 1.0:
            return ""
        return f"eta {remaining:.0f}s"

    controller.start(kind="fast", expected_seconds=2.0, message_builder=builder)
    assert statuses[-1] == "eta 2s"

    controller._emit_message(0.2)
    assert statuses == ["eta 2s"]
    assert summaries == ["eta 2s"]
