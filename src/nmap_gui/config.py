"""Runtime configuration loader for Rogue Finder."""
from __future__ import annotations

import argparse
import copy
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .storage_warnings import record_storage_warning

CONFIG_FILENAME = "rogue-finder.config.yaml"


def config_file_path(config_path: Path | str | None = None) -> Path:
    """Return the resolved configuration file path."""

    if config_path is None:
        return Path.cwd() / CONFIG_FILENAME
    if isinstance(config_path, Path):
        return config_path
    return Path(config_path)


DEFAULT_SETTINGS: dict[str, Any] = {
    "version": 1,
    "scan": {
        "default_timeout_seconds": 300,
        "fast_port_scan_list": [
            21,
            22,
            80,
            443,
            445,
            3389,
            5985,
            50000,
        ],
        "port_scan_list": [
            21,
            22,
            80,
            139,
            443,
            445,
            1433,
            3000,
            3306,
            3389,
            5432,
            5672,
            5900,
            5985,
            6379,
            8000,
            8080,
            8888,
            11211,
            15672,
            50000,
        ],
        "high_port_minimum": 50000,
        "advanced_timeout_seconds": 600,
        "advanced_max_parallel": 4,
    },
    "rating": {
        "icmp_points": 2,
        "port_weights": {
            21: 2,
            22: 0,
            80: 0,
            139: 0,
            1433: 1,
            3000: 1,
            3306: 1,
            3389: 2,
            443: 0,
            445: 2,
            5432: 1,
            5672: 2,
            5900: 0,
            5985: 2,
            6379: 2,
            8000: 1,
            8080: 1,
            8888: 1,
            11211: 2,
            15672: 2,
        },
        "combo_rules": [
            {"required": [22], "one_of": [3306, 5432], "points": 2},
            {"required": [3389, 1433], "points": 2},
            {"required": [8080, 5672, 15672], "points": 3},
        ],
        "high_port_bonus": {"port": 50000, "points": 1},
        "os_weights": {
            "windows": 3,
            "soho": 3,
            "iot": 3,
            "embedded": 3,
            "old linux": 2,
            "legacy linux": 2,
            "server": 1,
            "linux": 1,
            "unknown": 1,
        },
        "priority_thresholds": {
            "high": 8,
            "medium": 5,
        },
    },
    "ui": {
        "priority_colors": {
            "High": "#ffcccc",
            "Medium": "#fff0d2",
            "Low": "#d2ebff",
        }
    },
    "safe_scan": {
        "default_duration_seconds": 600.0,
        "history_limit": 20,
        "progress_update_ms": 500,
        "progress_visibility_ms": 4000,
        "timeout_seconds": 900,
        "max_parallel": 2,
    },
}


class ConfigurationError(RuntimeError):
    """Raised when the YAML configuration cannot be loaded."""


@dataclass(frozen=True)
class ScanSettings:
    default_timeout_seconds: int
    port_scan_list: tuple[int, ...]
    high_port_minimum: int
    fast_port_scan_list: tuple[int, ...]
    advanced_timeout_seconds: int
    advanced_max_parallel: int


@dataclass(frozen=True)
class ComboRule:
    required: tuple[int, ...]
    one_of: tuple[int, ...]
    points: int


@dataclass(frozen=True)
class RatingSettings:
    icmp_points: int
    port_weights: dict[int, int]
    combo_rules: tuple[ComboRule, ...]
    high_port_bonus_port: int
    high_port_bonus_points: int
    os_weights: dict[str, int]
    priority_high_threshold: int
    priority_medium_threshold: int


@dataclass(frozen=True)
class UiSettings:
    priority_colors: dict[str, str]


@dataclass(frozen=True)
class SafeScanSettings:
    default_duration_seconds: float
    history_limit: int
    progress_update_ms: int
    progress_visibility_ms: int
    timeout_seconds: int
    max_parallel: int


@dataclass(frozen=True)
class AppSettings:
    scan: ScanSettings
    rating: RatingSettings
    ui: UiSettings
    safe_scan: SafeScanSettings
    raw: dict[str, Any]


_SETTINGS_CACHE: AppSettings | None = None


def get_settings() -> AppSettings:
    """Return cached settings, loading from disk when necessary."""

    global _SETTINGS_CACHE
    if _SETTINGS_CACHE is None:
        _SETTINGS_CACHE = load_settings()
    return _SETTINGS_CACHE


def reset_settings_cache() -> None:
    """Reset the cached settings (useful for tests)."""

    global _SETTINGS_CACHE
    _SETTINGS_CACHE = None


def load_settings(config_path: Path | str | None = None) -> AppSettings:
    """Load settings from YAML, creating or merging defaults as needed."""

    path = config_file_path(config_path)
    try:
        data = _read_or_create_config(path)
    except yaml.YAMLError as exc:  # pragma: no cover - PyYAML formatting
        raise ConfigurationError(f"Failed to parse configuration file: {path}\n{exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"Configuration file must contain a mapping: {path}")
    merged = _merge_with_defaults(copy.deepcopy(DEFAULT_SETTINGS), data)
    if merged != data:
        _write_yaml(path, merged)
    return _build_settings(merged)


def write_default_config(destination: Path | str) -> Path:
    """Write the default configuration template to ``destination``."""

    target = Path(destination)
    _write_yaml(target, copy.deepcopy(DEFAULT_SETTINGS))
    return target


def merge_with_defaults(user_values: dict[str, Any] | None) -> dict[str, Any]:
    """Merge ``user_values`` with the default template without touching disk."""

    if user_values is None:
        user_values = {}
    return _merge_with_defaults(copy.deepcopy(DEFAULT_SETTINGS), user_values)


def write_settings(data: dict[str, Any], config_path: Path | str | None = None) -> bool:
    """Persist ``data`` to the configuration file location."""

    path = config_file_path(config_path)
    return _write_yaml(path, data)


def _read_or_create_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        _write_yaml(path, copy.deepcopy(DEFAULT_SETTINGS))
        return copy.deepcopy(DEFAULT_SETTINGS)
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    return loaded


def _write_yaml(path: Path, data: dict[str, Any]) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=False)
    except OSError as exc:  # pragma: no cover - depends on system perms
        LOGGER.warning("Failed to write configuration %s: %s", path, exc)
        record_storage_warning(scope="config", action="write", path=path, detail=str(exc))
        return False
    return True


def _merge_with_defaults(defaults: dict[str, Any], user_values: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for key in user_values:
        merged[key] = user_values[key]
    for key, value in defaults.items():
        if key not in user_values or user_values[key] is None:
            merged[key] = copy.deepcopy(value)
            continue
        if isinstance(value, dict) and isinstance(user_values.get(key), dict):
            merged[key] = _merge_with_defaults(value, user_values[key])
        else:
            merged[key] = user_values[key]
    return merged


def _build_settings(data: dict[str, Any]) -> AppSettings:
    scan = _build_scan_settings(data.get("scan", {}))
    rating = _build_rating_settings(data.get("rating", {}))
    ui = _build_ui_settings(data.get("ui", {}))
    safe_scan = _build_safe_scan_settings(data.get("safe_scan", {}))
    return AppSettings(scan=scan, rating=rating, ui=ui, safe_scan=safe_scan, raw=data)


def _build_scan_settings(data: dict[str, Any]) -> ScanSettings:
    scan_defaults = DEFAULT_SETTINGS["scan"]
    timeout = int(
        data.get("default_timeout_seconds", scan_defaults["default_timeout_seconds"])
    )
    high_port_min = int(data.get("high_port_minimum", scan_defaults["high_port_minimum"]))
    ports = tuple(int(port) for port in data.get("port_scan_list", ()))
    if not ports:
        ports = tuple(scan_defaults["port_scan_list"])
    fast_ports = tuple(int(port) for port in data.get("fast_port_scan_list", ()))
    if not fast_ports:
        fast_ports = tuple(scan_defaults["fast_port_scan_list"])
    advanced_timeout = int(
        data.get("advanced_timeout_seconds", scan_defaults["advanced_timeout_seconds"])
    )
    advanced_max = int(data.get("advanced_max_parallel", scan_defaults["advanced_max_parallel"]))
    if advanced_max <= 0:
        advanced_max = 1
    return ScanSettings(
        default_timeout_seconds=timeout,
        port_scan_list=ports,
        high_port_minimum=high_port_min,
        fast_port_scan_list=fast_ports,
        advanced_timeout_seconds=advanced_timeout,
        advanced_max_parallel=advanced_max,
    )


def _build_combo_rules(items: Iterable[dict[str, Any]]) -> tuple[ComboRule, ...]:
    rules = []
    for entry in items:
        required = tuple(int(port) for port in entry.get("required", []))
        one_of = tuple(int(port) for port in entry.get("one_of", []))
        points = int(entry.get("points", 0))
        if points <= 0:
            continue
        rules.append(ComboRule(required=required, one_of=one_of, points=points))
    return tuple(rules)


def _build_rating_settings(data: dict[str, Any]) -> RatingSettings:
    default_rating = DEFAULT_SETTINGS["rating"]
    icmp_points = int(data.get("icmp_points", default_rating["icmp_points"]))
    combo_rules = _build_combo_rules(data.get("combo_rules", []))
    if not combo_rules:
        combo_rules = _build_combo_rules(default_rating["combo_rules"])
    port_weights = {int(k): int(v) for k, v in data.get("port_weights", {}).items()}
    if not port_weights:
        port_weights = {int(k): int(v) for k, v in default_rating["port_weights"].items()}
    high_bonus = data.get("high_port_bonus", {}) or {}
    bonus_port = int(high_bonus.get("port", default_rating["high_port_bonus"]["port"]))
    bonus_points = int(high_bonus.get("points", default_rating["high_port_bonus"]["points"]))
    os_weights = {str(k): int(v) for k, v in data.get("os_weights", {}).items()}
    if not os_weights:
        os_weights = {str(k): int(v) for k, v in default_rating["os_weights"].items()}
    thresholds = data.get("priority_thresholds", {}) or {}
    high_threshold = int(
        thresholds.get("high", default_rating["priority_thresholds"]["high"])
    )
    medium_threshold = int(
        thresholds.get("medium", default_rating["priority_thresholds"]["medium"])
    )
    return RatingSettings(
        icmp_points=icmp_points,
        port_weights=port_weights,
        combo_rules=combo_rules,
        high_port_bonus_port=bonus_port,
        high_port_bonus_points=bonus_points,
        os_weights=os_weights,
        priority_high_threshold=high_threshold,
        priority_medium_threshold=medium_threshold,
    )


def _build_ui_settings(data: dict[str, Any]) -> UiSettings:
    colors = data.get("priority_colors") or {}
    if not colors:
        colors = DEFAULT_SETTINGS["ui"]["priority_colors"]
    return UiSettings(priority_colors={str(k): str(v) for k, v in colors.items()})


def _build_safe_scan_settings(data: dict[str, Any]) -> SafeScanSettings:
    defaults = DEFAULT_SETTINGS["safe_scan"]
    timeout_seconds = int(data.get("timeout_seconds", defaults["timeout_seconds"]))
    if timeout_seconds <= 0:
        timeout_seconds = defaults["timeout_seconds"]
    max_parallel = int(data.get("max_parallel", defaults["max_parallel"]))
    if max_parallel <= 0:
        max_parallel = 1
    return SafeScanSettings(
        default_duration_seconds=float(
            data.get("default_duration_seconds", defaults["default_duration_seconds"])
        ),
        history_limit=int(data.get("history_limit", defaults["history_limit"])),
        progress_update_ms=int(
            data.get("progress_update_ms", defaults["progress_update_ms"])
        ),
        progress_visibility_ms=int(
            data.get("progress_visibility_ms", defaults["progress_visibility_ms"])
        ),
        timeout_seconds=timeout_seconds,
        max_parallel=max_parallel,
    )


def main() -> None:  # pragma: no cover - CLI helper
    parser = argparse.ArgumentParser(description="Rogue Finder configuration utilities")
    parser.add_argument(
        "--write-default",
        dest="write_default",
        type=Path,
        help="Write the default configuration YAML to the provided path",
    )
    args = parser.parse_args()
    if args.write_default:
        target = write_default_config(args.write_default)
        print(f"Wrote default configuration to {target}")
        return
    settings = load_settings()
    config_path = Path.cwd() / CONFIG_FILENAME
    version = settings.raw.get("version", "n/a")
    print(f"Loaded configuration from {config_path}\nVersion: {version}")


if __name__ == "__main__":  # pragma: no cover - CLI
    main()

LOGGER = logging.getLogger(__name__)
