"""Regression tests for the CLI entrypoint helpers."""
from __future__ import annotations

import argparse

from nmap_gui import main as entry


def test_build_arg_parser_includes_debug_flag():
    parser = entry.build_arg_parser()
    assert isinstance(parser, argparse.ArgumentParser)
    args = parser.parse_args(["--debug"])
    assert args.debug is True


def test_main_exits_when_configuration_fails(monkeypatch):
    # Avoid importing PySide6 when running the test suite.
    monkeypatch.setitem(entry.__dict__, "QApplication", type("FakeApp", (), {"__call__": lambda *_: None}))

    class FakeWindow:
        def __init__(self, *args, **kwargs):
            pass

        def show(self):
            pass

    class FakeApplication:
        def __init__(self, *_):
            pass

        def exec(self):
            return 0

        def setWindowIcon(self, *_):
            pass

    monkeypatch.setitem(entry.__dict__, "QApplication", FakeApplication)
    monkeypatch.setitem(entry.__dict__, "MainWindow", FakeWindow)

    def fake_get_settings():
        raise entry.ConfigurationError("boom")

    monkeypatch.setitem(entry.__dict__, "get_settings", fake_get_settings)

    class DummyIcon:
        def isNull(self):
            return False

    monkeypatch.setitem(entry.__dict__, "load_app_icon", lambda: DummyIcon())

    class FakeMessageBox:
        def critical(self, *args, **kwargs):
            pass

    monkeypatch.setitem(entry.__dict__, "QMessageBox", FakeMessageBox())

    monkeypatch.setattr(entry.logging, "exception", lambda *_: None)

    assert entry.main([]) == 1
