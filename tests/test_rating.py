"""Unit tests for the rating engine."""
from __future__ import annotations

from dataclasses import replace

import pytest

from nmap_gui.config import DEFAULT_SETTINGS, ComboRule, get_settings
from nmap_gui.models import HostScanResult
from nmap_gui.rating import apply_rating, classify_os_guess

_RATING_DEFAULTS = DEFAULT_SETTINGS["rating"]
ICMP_POINTS = _RATING_DEFAULTS["icmp_points"]
MYSQL_PORT_WEIGHT = _RATING_DEFAULTS["port_weights"][3306]
HIGH_PORT_BONUS = _RATING_DEFAULTS["high_port_bonus"]["points"]
WINDOWS_OS_POINTS = _RATING_DEFAULTS["os_weights"]["windows"]
LEGACY_LINUX_POINTS = _RATING_DEFAULTS["os_weights"]["old linux"]
HIGH_PRIORITY_THRESHOLD = _RATING_DEFAULTS["priority_thresholds"]["high"]


def _combo_points(required_ports: set[int], one_of_ports: set[int]) -> int:
    for rule in _RATING_DEFAULTS["combo_rules"]:
        if set(rule.get("required", [])) == required_ports and set(rule.get("one_of", [])) == one_of_ports:
            return rule["points"]
    raise AssertionError("Matching combo rule not found.")


SSH_DB_COMBO_POINTS = _combo_points({22}, {3306, 5432})


def test_rating_hits_high_priority_when_rules_align() -> None:
    result = HostScanResult(
        target="198.51.100.5",
        is_alive=True,
        open_ports=[22, 3306, 50000],
        os_guess="Windows Server 2019",
    )

    rated = apply_rating(result)

    # Breakdown should include all contributing factors
    assert rated.score_breakdown["icmp"] == ICMP_POINTS
    assert rated.score_breakdown["port 3306"] == MYSQL_PORT_WEIGHT
    assert rated.score_breakdown["high port 50000"] == HIGH_PORT_BONUS
    assert rated.score_breakdown["os:windows"] == WINDOWS_OS_POINTS
    assert rated.score_breakdown["combo 22+3306"] == SSH_DB_COMBO_POINTS
    assert rated.priority == "High"
    assert rated.score >= HIGH_PRIORITY_THRESHOLD


def test_combo_rule_requires_all_ports() -> None:
    result = HostScanResult(
        target="198.51.100.6",
        is_alive=True,
        open_ports=[8080, 5672],  # missing 15672 so combo should not trigger
        os_guess="Linux",
    )

    rated = apply_rating(result)

    assert "combo 5672+8080+15672" not in rated.score_breakdown
    # Score should only reflect ICMP, OS, and weighted ports (8080 -> +1)
    expected_score = (
        rated.score_breakdown["icmp"]
        + rated.score_breakdown["port 8080"]
        + rated.score_breakdown["port 5672"]
        + rated.score_breakdown["os:server"]
    )
    assert rated.score == expected_score


def test_legacy_linux_detection_adds_correct_points() -> None:
    result = HostScanResult(
        target="198.51.100.7",
        is_alive=False,
        open_ports=[],
        os_guess="Ubuntu 12.04 LTS (Linux 3.2)",
    )

    rated = apply_rating(result)

    assert rated.score_breakdown["os:old linux"] == LEGACY_LINUX_POINTS
    assert rated.priority == "Low"


@pytest.mark.parametrize(
    ("guess", "expected"),
    [
        ("Windows 11 Pro", "windows"),
        ("SOHO router appliance", "soho"),
        ("Ubuntu Server 22 LTS", "server"),
        ("Linux 2.6.32 host", "old linux"),
        ("", "unknown"),
    ],
)
def test_classify_os_guess_variants(guess: str, expected: str) -> None:
    assert classify_os_guess(guess) == expected


def test_combo_one_of_rule_requires_match() -> None:
    result = HostScanResult(
        target="198.51.100.8",
        is_alive=True,
        open_ports=[22],
        os_guess="Windows",  # ensures icmp + os contribute
    )

    rated = apply_rating(result)

    assert not any(key.startswith("combo 22+") for key in rated.score_breakdown)
    expected_score = rated.score_breakdown["icmp"] + rated.score_breakdown["os:windows"]
    assert rated.score == expected_score


def test_combo_rules_handle_empty_and_one_of_only() -> None:
    base_settings = get_settings().rating
    custom_weights = dict(base_settings.port_weights)
    weight_8443 = 2
    combo_points = 4
    custom_weights[8443] = weight_8443
    custom_rules = (
        ComboRule(required=(), one_of=(), points=10),  # ignored due to empty rule
        ComboRule(required=(), one_of=(8443,), points=combo_points),
    )
    custom_settings = replace(
        base_settings,
        port_weights=custom_weights,
        combo_rules=custom_rules,
    )
    result = HostScanResult(
        target="198.51.100.9",
        is_alive=False,
        open_ports=[8443],
        os_guess="mystery",
    )

    rated = apply_rating(result, settings=custom_settings)

    combo_keys = {key for key in rated.score_breakdown if key.startswith("combo")}
    assert combo_keys == {"combo 8443"}
    assert rated.score_breakdown["combo 8443"] == combo_points
    assert rated.score_breakdown["port 8443"] == weight_8443


def test_priority_medium_band() -> None:
    result = HostScanResult(
        target="198.51.100.10",
        is_alive=True,
        open_ports=[3389],
        os_guess="Linux",
    )

    rated = apply_rating(result)

    assert rated.score == (
        rated.score_breakdown["icmp"]
        + rated.score_breakdown["port 3389"]
        + rated.score_breakdown["os:server"]
    )
    assert rated.priority == "Medium"
