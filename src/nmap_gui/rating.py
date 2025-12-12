"""Rating engine implementation."""
from __future__ import annotations

from dataclasses import replace
from typing import Dict, Iterable

from .config import RatingSettings, get_settings
from .models import HostScanResult


def classify_os_guess(os_guess: str) -> str:
    guess = (os_guess or "").lower()
    if "windows" in guess:
        return "windows"
    if "soho" in guess or "router" in guess or "iot" in guess:
        return "soho"
    if "centos" in guess or "ubuntu" in guess or "linux" in guess:
        if any(token in guess for token in ("2.", "3.", "4.", "legacy", "old")):
            return "old linux"
        return "server"
    return "unknown"


def apply_rating(
    result: HostScanResult,
    settings: RatingSettings | None = None,
) -> HostScanResult:
    """Apply rating rules and return a new HostScanResult."""

    rating_settings = settings or get_settings().rating

    breakdown: Dict[str, int] = {}
    score = 0
    score += _score_icmp(result, rating_settings, breakdown)
    score += _score_ports(result.open_ports, rating_settings, breakdown)
    score += _score_os(result.os_guess, rating_settings, breakdown)
    score += _score_combos(result.open_ports, rating_settings, breakdown)
    priority = _determine_priority(score, rating_settings)

    return replace(result, score=score, priority=priority, score_breakdown=breakdown)


def _score_icmp(result: HostScanResult, settings: RatingSettings, breakdown: Dict[str, int]) -> int:
    if not result.is_alive:
        return 0
    breakdown["icmp"] = settings.icmp_points
    return settings.icmp_points


def _score_ports(
    open_ports: Iterable[int],
    settings: RatingSettings,
    breakdown: Dict[str, int],
) -> int:
    score = 0
    high_port_bonus_port = settings.high_port_bonus_port
    high_port_bonus_points = settings.high_port_bonus_points
    for port in open_ports:
        points = settings.port_weights.get(port, 0)
        if points:
            key = f"port {port}"
            breakdown[key] = breakdown.get(key, 0) + points
            score += points
        if high_port_bonus_points and port == high_port_bonus_port:
            key = f"high port {high_port_bonus_port}"
            breakdown[key] = breakdown.get(key, 0) + high_port_bonus_points
            score += high_port_bonus_points
    return score


def _score_os(os_guess: str, settings: RatingSettings, breakdown: Dict[str, int]) -> int:
    os_class = classify_os_guess(os_guess)
    os_points = settings.os_weights.get(os_class, 1)
    breakdown[f"os:{os_class}"] = os_points
    return os_points


def _score_combos(
    open_ports: Iterable[int],
    settings: RatingSettings,
    breakdown: Dict[str, int],
) -> int:
    open_port_set = set(open_ports)
    score = 0
    for rule in settings.combo_rules:
        required = set(rule.required)
        if required and not required.issubset(open_port_set):
            continue
        matched_one_of = [port for port in rule.one_of if port in open_port_set] if rule.one_of else []
        if rule.one_of and not matched_one_of:
            continue
        if not rule.one_of and not required:
            continue
        key_parts = sorted(required.union(matched_one_of))
        key = "+".join(str(port) for port in key_parts)
        breakdown[f"combo {key}"] = rule.points
        score += rule.points
    return score


def _determine_priority(score: int, settings: RatingSettings) -> str:
    if score >= settings.priority_high_threshold:
        return "High"
    if score >= settings.priority_medium_threshold:
        return "Medium"
    return "Low"
