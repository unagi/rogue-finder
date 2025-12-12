"""Core data models for the Nmap GUI discovery and rating tool."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
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
class ScanLogEvent:
    """Structured log line emitted while an nmap phase is running."""

    target: str
    phase: ScanMode | None
    stream: str
    line: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class ErrorRecord:
    """Structured error payload with translation keys and remediation hints."""

    code: str
    message_key: str
    action_key: str
    context: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "code": self.code,
            "message_key": self.message_key,
            "action_key": self.action_key,
            "context": dict(self.context),
        }


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
    errors: List[ErrorRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON/export friendly representation."""

        data = asdict(self)
        data["errors"] = [error.to_dict() for error in self.errors]
        return data


@dataclass
class SafeScanReport:
    """Result payload for an on-demand safe script diagnostic run."""

    target: str
    command: str
    started_at: datetime
    finished_at: datetime
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    errors: List[ErrorRecord] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return max((self.finished_at - self.started_at).total_seconds(), 0.0)

    @property
    def success(self) -> bool:
        return not self.errors and (self.exit_code == 0)


def sanitize_targets(raw_value: str) -> List[str]:
    """Turn the input string into a clean list of targets."""

    if not raw_value:
        return []
    separators = [",", "\n", "\t", ";"]
    normalized = raw_value
    for sep in separators:
        normalized = normalized.replace(sep, " ")
    return [item.strip() for item in normalized.split(" ") if item.strip()]
