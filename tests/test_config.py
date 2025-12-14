"""Tests for configuration loader behavior."""
from __future__ import annotations

import yaml

from nmap_gui.gui.controller.config_controller import ConfigController
from nmap_gui.infrastructure.config import DEFAULT_SETTINGS

USER_TIMEOUT_OVERRIDE = 123


def test_load_settings_creates_file_when_missing(tmp_path):
    controller = ConfigController()
    cfg_path = tmp_path / "rogue-finder.config.yaml"

    settings = controller.load_settings(cfg_path)

    assert cfg_path.exists()
    assert settings.scan.port_scan_list
    data = yaml.safe_load(cfg_path.read_text())
    assert data["version"] == DEFAULT_SETTINGS["version"]


def test_load_settings_merges_and_preserves_unknown_keys(tmp_path):
    controller = ConfigController()
    cfg_path = tmp_path / "rogue-finder.config.yaml"
    initial = {
        "scan": {"default_timeout_seconds": USER_TIMEOUT_OVERRIDE, "custom_note": "keep"},
        "rating": {"icmp_points": 5},
        "extra_top_level": {"foo": "bar"},
    }
    cfg_path.write_text(yaml.safe_dump(initial, sort_keys=False))

    settings = controller.load_settings(cfg_path)

    assert settings.scan.default_timeout_seconds == USER_TIMEOUT_OVERRIDE
    data = yaml.safe_load(cfg_path.read_text())
    assert "port_scan_list" in data["scan"]
    assert data["scan"]["custom_note"] == "keep"
    assert data["extra_top_level"] == {"foo": "bar"}


def test_reset_settings_cache_allows_reload(tmp_path, monkeypatch):
    controller = ConfigController()
    cfg_path = tmp_path / "rogue-finder.config.yaml"
    monkeypatch.chdir(tmp_path)
    cfg_path.write_text(yaml.safe_dump(DEFAULT_SETTINGS))
    controller.reset_cache()
    loaded_first = controller.current_settings()
    cfg_path.write_text(
        yaml.safe_dump({**DEFAULT_SETTINGS, "version": 99}, sort_keys=False)
    )
    controller.reset_cache()
    loaded_second = controller.current_settings()
    assert loaded_first.raw["version"] != loaded_second.raw["version"]


def test_merge_with_defaults_adds_missing_values():
    controller = ConfigController()
    merged = controller.merge_with_defaults(
        {"scan": {"default_timeout_seconds": USER_TIMEOUT_OVERRIDE}}
    )

    assert merged["scan"]["default_timeout_seconds"] == USER_TIMEOUT_OVERRIDE
    assert merged["scan"]["port_scan_list"]


def test_write_settings_persists_changes(tmp_path):
    controller = ConfigController()
    cfg_path = tmp_path / "rogue-finder.config.yaml"
    payload = controller.merge_with_defaults(
        {"scan": {"default_timeout_seconds": USER_TIMEOUT_OVERRIDE}}
    )

    assert controller.write_settings(payload, cfg_path)
    data = yaml.safe_load(cfg_path.read_text())
    assert data["scan"]["default_timeout_seconds"] == USER_TIMEOUT_OVERRIDE


def test_resolve_path_round_trip(tmp_path):
    controller = ConfigController()
    target = tmp_path / "custom.yaml"

    resolved = controller.resolve_path(target)

    assert resolved == target
