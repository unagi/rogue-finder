"""Runtime configuration loader for Rogue Finder."""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

import yaml


CONFIG_FILENAME = "rogue-finder.config.yaml"


DEFAULT_SETTINGS: Dict[str, Any] = {
    "version": 1,
    "scan": {
        "default_timeout_seconds": 300,
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
        "default_duration_seconds": 120.0,
        "history_limit": 20,
        "progress_update_ms": 500,
        "progress_visibility_ms": 4000,
    },
}


class ConfigurationError(RuntimeError):
    """Raised when the YAML configuration cannot be loaded."""


@dataclass(frozen=True)
class ScanSettings:
    default_timeout_seconds: int
    port_scan_list: Tuple[int, ...]
    high_port_minimum: int


@dataclass(frozen=True)
class ComboRule:
    required: Tuple[int, ...]
    one_of: Tuple[int, ...]
    points: int


@dataclass(frozen=True)
class RatingSettings:
    icmp_points: int
    port_weights: Dict[int, int]
    combo_rules: Tuple[ComboRule, ...]
    high_port_bonus_port: int
    high_port_bonus_points: int
    os_weights: Dict[str, int]
    priority_high_threshold: int
    priority_medium_threshold: int


@dataclass(frozen=True)
class UiSettings:
    priority_colors: Dict[str, str]


@dataclass(frozen=True)
class SafeScanSettings:
    default_duration_seconds: float
    history_limit: int
    progress_update_ms: int
    progress_visibility_ms: int


@dataclass(frozen=True)
class AppSettings:
    scan: ScanSettings
    rating: RatingSettings
    ui: UiSettings
    safe_scan: SafeScanSettings
    raw: Dict[str, Any]


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

    path = Path(config_path) if config_path else Path.cwd() / CONFIG_FILENAME
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


def _read_or_create_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        _write_yaml(path, copy.deepcopy(DEFAULT_SETTINGS))
        return copy.deepcopy(DEFAULT_SETTINGS)
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    return loaded


def _write_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=False)


def _merge_with_defaults(defaults: Dict[str, Any], user_values: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
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


def _build_settings(data: Dict[str, Any]) -> AppSettings:
    scan = _build_scan_settings(data.get("scan", {}))
    rating = _build_rating_settings(data.get("rating", {}))
    ui = _build_ui_settings(data.get("ui", {}))
    safe_scan = _build_safe_scan_settings(data.get("safe_scan", {}))
    return AppSettings(scan=scan, rating=rating, ui=ui, safe_scan=safe_scan, raw=data)


def _build_scan_settings(data: Dict[str, Any]) -> ScanSettings:
    timeout = int(data.get("default_timeout_seconds", DEFAULT_SETTINGS["scan"]["default_timeout_seconds"]))
    high_port_min = int(data.get("high_port_minimum", DEFAULT_SETTINGS["scan"]["high_port_minimum"]))
    ports = tuple(int(port) for port in data.get("port_scan_list", ()))
    if not ports:
        ports = tuple(DEFAULT_SETTINGS["scan"]["port_scan_list"])
    return ScanSettings(
        default_timeout_seconds=timeout,
        port_scan_list=ports,
        high_port_minimum=high_port_min,
    )


def _build_combo_rules(items: Iterable[Dict[str, Any]]) -> Tuple[ComboRule, ...]:
    rules = []
    for entry in items:
        required = tuple(int(port) for port in entry.get("required", []))
        one_of = tuple(int(port) for port in entry.get("one_of", []))
        points = int(entry.get("points", 0))
        if points <= 0:
            continue
        rules.append(ComboRule(required=required, one_of=one_of, points=points))
    return tuple(rules)


def _build_rating_settings(data: Dict[str, Any]) -> RatingSettings:
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
    high_threshold = int(thresholds.get("high", default_rating["priority_thresholds"]["high"]))
    medium_threshold = int(thresholds.get("medium", default_rating["priority_thresholds"]["medium"]))
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


def _build_ui_settings(data: Dict[str, Any]) -> UiSettings:
    colors = data.get("priority_colors") or {}
    if not colors:
        colors = DEFAULT_SETTINGS["ui"]["priority_colors"]
    return UiSettings(priority_colors={str(k): str(v) for k, v in colors.items()})


def _build_safe_scan_settings(data: Dict[str, Any]) -> SafeScanSettings:
    defaults = DEFAULT_SETTINGS["safe_scan"]
    return SafeScanSettings(
        default_duration_seconds=float(data.get("default_duration_seconds", defaults["default_duration_seconds"])),
        history_limit=int(data.get("history_limit", defaults["history_limit"])),
        progress_update_ms=int(data.get("progress_update_ms", defaults["progress_update_ms"])),
        progress_visibility_ms=int(data.get("progress_visibility_ms", defaults["progress_visibility_ms"])),
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
    print(f"Loaded configuration from {Path.cwd() / CONFIG_FILENAME}\nVersion: {settings.raw.get('version', 'n/a')}")


if __name__ == "__main__":  # pragma: no cover - CLI
    main()
