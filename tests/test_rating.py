"""Unit tests for the rating engine."""
from __future__ import annotations

from nmap_gui.models import HostScanResult
from nmap_gui.rating import apply_rating


def test_rating_hits_high_priority_when_rules_align() -> None:
    result = HostScanResult(
        target="10.0.0.5",
        is_alive=True,
        open_ports=[22, 3306, 50000],
        os_guess="Windows Server 2019",
    )

    rated = apply_rating(result)

    # Breakdown should include all contributing factors
    assert rated.score_breakdown["icmp"] == 2
    assert rated.score_breakdown["port 3306"] == 1
    assert rated.score_breakdown["high port 50000"] == 1
    assert rated.score_breakdown["os:windows"] == 3
    assert rated.score_breakdown["combo 22+3306"] == 2
    assert rated.priority == "High"
    assert rated.score >= 8


def test_combo_rule_requires_all_ports() -> None:
    result = HostScanResult(
        target="10.0.0.6",
        is_alive=True,
        open_ports=[8080, 5672],  # missing 15672 so combo should not trigger
        os_guess="Linux",
    )

    rated = apply_rating(result)

    assert "combo 5672+8080+15672" not in rated.score_breakdown
    # Score should only reflect ICMP, OS, and weighted ports (8080 -> +1)
    assert rated.score == 2 + 1 + 2 + rated.score_breakdown["os:server"]


def test_legacy_linux_detection_adds_correct_points() -> None:
    result = HostScanResult(
        target="10.0.0.7",
        is_alive=False,
        open_ports=[],
        os_guess="Ubuntu 12.04 LTS (Linux 3.2)",
    )

    rated = apply_rating(result)

    assert rated.score_breakdown["os:old linux"] == 2
    assert rated.priority == "Low"
