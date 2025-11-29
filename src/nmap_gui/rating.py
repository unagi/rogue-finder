"""Rating engine implementation."""
from __future__ import annotations

from dataclasses import replace
from typing import Dict, Iterable

from .models import HostScanResult

PORT_WEIGHTS = {
    21: 2,
    22: 0,  # base weight handled via combos
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
}

COMBO_RULES = [
    {"required": {22}, "one_of": {3306, 5432}, "points": 2},
    {"required": {3389, 1433}, "points": 2},
    {"required": {8080, 5672, 15672}, "points": 3},
]

OS_WEIGHTS = {
    "windows": 3,
    "soho": 3,
    "iot": 3,
    "embedded": 3,
    "old linux": 2,
    "legacy linux": 2,
    "linux": 1,
    "server": 1,
    "unknown": 1,
}


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


def apply_rating(result: HostScanResult) -> HostScanResult:
    """Apply rating rules and return a new HostScanResult."""

    breakdown: Dict[str, int] = {}
    score = 0

    if result.is_alive:
        breakdown["icmp"] = 2
        score += 2

    for port in result.open_ports:
        points = PORT_WEIGHTS.get(port, 0)
        if points:
            breakdown[f"port {port}"] = breakdown.get(f"port {port}", 0) + points
            score += points
        if port == 50000:
            breakdown["high port 50000"] = breakdown.get("high port 50000", 0) + 1
            score += 1

    os_class = classify_os_guess(result.os_guess)
    os_points = OS_WEIGHTS.get(os_class, 1)
    breakdown[f"os:{os_class}"] = os_points
    score += os_points

    open_port_set = set(result.open_ports)
    for rule in COMBO_RULES:
        required = set(rule.get("required", set()))
        one_of: Iterable[int] = rule.get("one_of", set())
        points = rule["points"]
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
    if score >= 8:
        priority = "High"
    elif score >= 5:
        priority = "Medium"

    return replace(result, score=score, priority=priority, score_breakdown=breakdown)
