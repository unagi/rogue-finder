"""Tests for configuration loader behavior."""
from __future__ import annotations

import yaml

from nmap_gui import config

USER_TIMEOUT_OVERRIDE = 123


def test_load_settings_creates_file_when_missing(tmp_path):
    cfg_path = tmp_path / "rogue-finder.config.yaml"

    settings = config.load_settings(cfg_path)

    assert cfg_path.exists()
    assert settings.scan.port_scan_list
    # File should contain default version marker
    data = yaml.safe_load(cfg_path.read_text())
    assert data["version"] == config.DEFAULT_SETTINGS["version"]


def test_load_settings_merges_and_preserves_unknown_keys(tmp_path):
    cfg_path = tmp_path / "rogue-finder.config.yaml"
    initial = {
        "scan": {"default_timeout_seconds": USER_TIMEOUT_OVERRIDE, "custom_note": "keep"},
        "rating": {"icmp_points": 5},
        "extra_top_level": {"foo": "bar"},
    }
    cfg_path.write_text(yaml.safe_dump(initial, sort_keys=False))

    settings = config.load_settings(cfg_path)

    # User override should win
    assert settings.scan.default_timeout_seconds == USER_TIMEOUT_OVERRIDE
    # Missing defaults should now be written back to disk
    data = yaml.safe_load(cfg_path.read_text())
    assert "port_scan_list" in data["scan"]
    # Custom keys should persist
    assert data["scan"]["custom_note"] == "keep"
    assert data["extra_top_level"] == {"foo": "bar"}


def test_reset_settings_cache_allows_reload(tmp_path, monkeypatch):
    cfg_path = tmp_path / "rogue-finder.config.yaml"
    monkeypatch.chdir(tmp_path)
    cfg_path.write_text(yaml.safe_dump(config.DEFAULT_SETTINGS))
    config.reset_settings_cache()
    loaded_first = config.get_settings()
    cfg_path.write_text(
        yaml.safe_dump({**config.DEFAULT_SETTINGS, "version": 99}, sort_keys=False)
    )
    config.reset_settings_cache()
    loaded_second = config.get_settings()
    assert loaded_first.raw["version"] != loaded_second.raw["version"]


def test_merge_with_defaults_adds_missing_values():
    merged = config.merge_with_defaults({"scan": {"default_timeout_seconds": USER_TIMEOUT_OVERRIDE}})

    assert merged["scan"]["default_timeout_seconds"] == USER_TIMEOUT_OVERRIDE
    assert merged["scan"]["port_scan_list"]  # default injected


def test_write_settings_persists_changes(tmp_path):
    cfg_path = tmp_path / "rogue-finder.config.yaml"
    payload = config.merge_with_defaults({"scan": {"default_timeout_seconds": USER_TIMEOUT_OVERRIDE}})

    assert config.write_settings(payload, cfg_path)
    data = yaml.safe_load(cfg_path.read_text())
    assert data["scan"]["default_timeout_seconds"] == USER_TIMEOUT_OVERRIDE
