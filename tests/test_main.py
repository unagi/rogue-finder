"""Regression tests for the CLI entrypoint helpers."""
from __future__ import annotations

import argparse
import sys
import types

from nmap_gui import main as entry


def _stub_app_icon(monkeypatch, icon):
    module = types.ModuleType("nmap_gui.gui.app_icon")
    module.load_app_icon = lambda: icon
    monkeypatch.setitem(sys.modules, "nmap_gui.gui.app_icon", module)


def test_build_arg_parser_includes_debug_flag():
    parser = entry.build_arg_parser()
    assert isinstance(parser, argparse.ArgumentParser)
    args = parser.parse_args(["--debug"])
    assert args.debug is True


def test_main_exits_when_configuration_fails(monkeypatch):
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

    class DummyIcon:
        def isNull(self):
            return True

    class FakeMessageBox:
        def critical(self, *args, **kwargs):
            self.called = True

    fake_message_box = FakeMessageBox()
    monkeypatch.setattr(entry, "QApplication", FakeApplication)
    monkeypatch.setattr(entry, "MainWindow", FakeWindow)
    monkeypatch.setattr(entry, "QMessageBox", fake_message_box)
    monkeypatch.setattr(entry.mp, "freeze_support", lambda: None)
    monkeypatch.setattr(entry.logging, "exception", lambda *_: None)

    def fake_get_settings():
        raise entry.ConfigurationError("boom")

    monkeypatch.setattr(entry, "get_settings", fake_get_settings)
    _stub_app_icon(monkeypatch, DummyIcon())

    assert entry.main([]) == 1
    assert getattr(fake_message_box, "called", False) is True


def test_main_runs_success_path(monkeypatch):
    events: dict[str, object] = {}
    expected_exit_code = 7

    class FakeIcon:
        def __init__(self):
            self.null = False

        def isNull(self):
            return self.null

    class FakeApplication:
        def __init__(self, argv):
            events["argv"] = list(argv)
            self.icon = None

        def setWindowIcon(self, icon):
            self.icon = icon
            events["icon_set"] = icon

        def exec(self):
            return expected_exit_code

    class FakeWindow:
        def __init__(self, settings, app_icon):
            events["window_settings"] = settings
            events["window_icon"] = app_icon
            self.show_called = False

        def show(self):
            self.show_called = True
            events["window_shown"] = True

    class FakeSettings:
        pass

    monkeypatch.setattr(entry, "QApplication", FakeApplication)
    monkeypatch.setattr(entry, "MainWindow", FakeWindow)
    monkeypatch.setattr(entry, "get_settings", lambda: FakeSettings())
    monkeypatch.setattr(entry.mp, "freeze_support", lambda: None)
    monkeypatch.setattr(entry, "QMessageBox", types.SimpleNamespace(critical=lambda *args, **kwargs: None))
    icon = FakeIcon()
    _stub_app_icon(monkeypatch, icon)

    result = entry.main(["--debug"])

    assert result == expected_exit_code
    assert events["window_shown"] is True
    assert events["window_icon"] is icon
