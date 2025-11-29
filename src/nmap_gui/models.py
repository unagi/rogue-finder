"""Core data models for the Nmap GUI discovery and rating tool."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import Dict, List, Sequence, Set


class ScanMode(Enum):
    """Supported scan phases."""

    ICMP = auto()
    PORTS = auto()
    OS = auto()


@dataclass(frozen=True)
class ScanConfig:
    """User-supplied scan configuration."""

    targets: Sequence[str]
    scan_modes: Set[ScanMode]


@dataclass
class HostScanResult:
    """Structured data extracted from nmap XML output and rating stage."""

    target: str
    is_alive: bool = False
    open_ports: List[int] = field(default_factory=list)
    os_guess: str = "Unknown"
    os_accuracy: int | None = None
    high_ports: List[int] = field(default_factory=list)
    score_breakdown: Dict[str, int] = field(default_factory=dict)
    score: int = 0
    priority: str = "Unknown"
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON/export friendly representation."""

        data = asdict(self)
        return data


def sanitize_targets(raw_value: str) -> List[str]:
    """Turn the input string into a clean list of targets."""

    if not raw_value:
        return []
    separators = [",", "\n", "\t", ";"]
    normalized = raw_value
    for sep in separators:
        normalized = normalized.replace(sep, " ")
    return [item.strip() for item in normalized.split(" ") if item.strip()]
