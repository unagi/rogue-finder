"""Rating engine implementation."""
from __future__ import annotations

from dataclasses import replace
from typing import Dict

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

    if result.is_alive:
        breakdown["icmp"] = rating_settings.icmp_points
        score += rating_settings.icmp_points

    high_port_bonus_port = rating_settings.high_port_bonus_port
    high_port_bonus_points = rating_settings.high_port_bonus_points

    for port in result.open_ports:
        points = rating_settings.port_weights.get(port, 0)
        if points:
            breakdown[f"port {port}"] = breakdown.get(f"port {port}", 0) + points
            score += points
        if high_port_bonus_points and port == high_port_bonus_port:
            key = f"high port {high_port_bonus_port}"
            breakdown[key] = breakdown.get(key, 0) + high_port_bonus_points
            score += high_port_bonus_points

    os_class = classify_os_guess(result.os_guess)
    os_points = rating_settings.os_weights.get(os_class, 1)
    breakdown[f"os:{os_class}"] = os_points
    score += os_points

    open_port_set = set(result.open_ports)
    for rule in rating_settings.combo_rules:
        required = set(rule.required)
        one_of = rule.one_of
        points = rule.points
        if required and not required.issubset(open_port_set):
            continue
        matched_one_of = [port for port in one_of if port in open_port_set] if one_of else []
        if one_of and not matched_one_of:
            continue
        if not one_of and not required:
            continue
        key_parts = sorted(required.union(matched_one_of))
        key = "+".join(str(p) for p in key_parts)
        breakdown[f"combo {key}"] = points
        score += points

    priority = "Low"
    if score >= rating_settings.priority_high_threshold:
        priority = "High"
    elif score >= rating_settings.priority_medium_threshold:
        priority = "Medium"

    return replace(result, score=score, priority=priority, score_breakdown=breakdown)
