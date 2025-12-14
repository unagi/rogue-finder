"""Core data models for the Nmap GUI discovery and rating tool."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto
from typing import Any


class ScanMode(Enum):
    """Supported scan phases."""

    ICMP = auto()
    PORTS = auto()
    OS = auto()


@dataclass(frozen=True)
class ScanConfig:
    """User-supplied scan configuration."""

    targets: Sequence[str]
    scan_modes: set[ScanMode]
    port_list: tuple[int, ...] | None = None
    timeout_seconds: int | None = None
    max_parallel: int | None = None
    detail_label: str = "fast"


@dataclass
class ScanLogEvent:
    """Structured log line emitted while an nmap phase is running."""

    target: str
    phase: ScanMode | None
    stream: str
    line: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_message(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "phase": self.phase.name if self.phase else None,
            "stream": self.stream,
            "line": self.line,
            "timestamp": self.timestamp.isoformat(),
        }

    @staticmethod
    def from_message(payload: dict[str, Any]) -> ScanLogEvent:
        phase_name = payload.get("phase")
        phase = ScanMode[phase_name] if phase_name else None
        timestamp_text = payload.get("timestamp")
        if timestamp_text:
            try:
                timestamp = datetime.fromisoformat(timestamp_text)
            except ValueError:
                timestamp = datetime.now(UTC)
        else:
            timestamp = datetime.now(UTC)
        return ScanLogEvent(
            target=str(payload.get("target", "")),
            phase=phase,
            stream=str(payload.get("stream", "")),
            line=str(payload.get("line", "")),
            timestamp=timestamp,
        )

@dataclass
class ErrorRecord:
    """Structured error payload with translation keys and remediation hints."""

    code: str
    message_key: str
    action_key: str
    context: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "message_key": self.message_key,
            "action_key": self.action_key,
            "context": dict(self.context),
        }

    @staticmethod
    def from_dict(payload: dict[str, Any]) -> ErrorRecord:
        context = payload.get("context") or {}
        return ErrorRecord(
            code=str(payload.get("code", "")),
            message_key=str(payload.get("message_key", "")),
            action_key=str(payload.get("action_key", "")),
            context={str(k): str(v) for k, v in context.items()},
        )


@dataclass
class HostScanResult:
    """Structured data extracted from nmap XML output and rating stage."""

    target: str
    is_alive: bool = False
    open_ports: list[int] = field(default_factory=list)
    os_guess: str = "Unknown"
    os_accuracy: int | None = None
    high_ports: list[int] = field(default_factory=list)
    score_breakdown: dict[str, int] = field(default_factory=dict)
    score: int = 0
    priority: str = "Unknown"
    errors: list[ErrorRecord] = field(default_factory=list)
    detail_level: str = "fast"
    detail_updated_at: str | None = None
    diagnostics_status: str = "not_started"
    diagnostics_updated_at: str | None = None
    is_placeholder: bool = False
    diagnostics_report: SafeScanReport | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON/export friendly representation."""

        data = asdict(self)
        data["errors"] = [error.to_dict() for error in self.errors]
        report = self.diagnostics_report
        if report:
            data["diagnostics_report"] = {
                "target": report.target,
                "command": report.command,
                "started_at": report.started_at.isoformat(),
                "finished_at": report.finished_at.isoformat(),
                "stdout": report.stdout,
                "stderr": report.stderr,
                "exit_code": report.exit_code,
                "errors": [error.to_dict() for error in report.errors],
            }
        else:
            data["diagnostics_report"] = None
        return data

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> HostScanResult:
        errors = [ErrorRecord.from_dict(item) for item in payload.get("errors", [])]
        result = cls(
            target=str(payload.get("target", "")),
            is_alive=bool(payload.get("is_alive", False)),
            open_ports=list(payload.get("open_ports", [])),
            os_guess=str(payload.get("os_guess", "Unknown")),
            os_accuracy=payload.get("os_accuracy"),
            high_ports=list(payload.get("high_ports", [])),
            score_breakdown=dict(payload.get("score_breakdown", {})),
            score=int(payload.get("score", 0)),
            priority=str(payload.get("priority", "Unknown")),
            errors=errors,
            detail_level=str(payload.get("detail_level", "fast")),
            detail_updated_at=payload.get("detail_updated_at"),
            diagnostics_status=str(payload.get("diagnostics_status", "not_started")),
            diagnostics_updated_at=payload.get("diagnostics_updated_at"),
            is_placeholder=bool(payload.get("is_placeholder", False)),
        )
        report_payload = payload.get("diagnostics_report")
        if report_payload:
            result.diagnostics_report = SafeScanReport(
                target=str(report_payload.get("target", result.target)),
                command=str(report_payload.get("command", "")),
                started_at=datetime.fromisoformat(report_payload["started_at"])
                if report_payload.get("started_at")
                else datetime.now(UTC),
                finished_at=datetime.fromisoformat(report_payload["finished_at"])
                if report_payload.get("finished_at")
                else datetime.now(UTC),
                stdout=str(report_payload.get("stdout", "")),
                stderr=str(report_payload.get("stderr", "")),
                exit_code=report_payload.get("exit_code"),
                errors=[ErrorRecord.from_dict(item) for item in report_payload.get("errors", [])],
            )
        return result


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
    errors: list[ErrorRecord] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return max((self.finished_at - self.started_at).total_seconds(), 0.0)

    @property
    def success(self) -> bool:
        return not self.errors and (self.exit_code == 0)


def sanitize_targets(raw_value: str) -> list[str]:
    """Turn the input string into a clean list of targets."""

    if not raw_value:
        return []
    separators = [",", "\n", "\t", ";"]
    normalized = raw_value
    for sep in separators:
        normalized = normalized.replace(sep, " ")
    return [item.strip() for item in normalized.split(" ") if item.strip()]


def serialize_scan_config(config: ScanConfig) -> dict[str, Any]:
    return {
        "targets": list(config.targets),
        "scan_modes": [mode.name for mode in config.scan_modes],
        "port_list": list(config.port_list) if config.port_list else None,
        "timeout_seconds": config.timeout_seconds,
        "max_parallel": config.max_parallel,
        "detail_label": config.detail_label,
    }


def deserialize_scan_config(payload: dict[str, Any]) -> ScanConfig:
    scan_mode_names = payload.get("scan_modes") or []
    modes = {ScanMode[name] for name in scan_mode_names}
    port_list = payload.get("port_list")
    timeout = payload.get("timeout_seconds")
    max_parallel = payload.get("max_parallel")
    detail_label = payload.get("detail_label", "fast")
    return ScanConfig(
        targets=payload.get("targets", []),
        scan_modes=modes,
        port_list=tuple(port_list) if port_list else None,
        timeout_seconds=int(timeout) if timeout is not None else None,
        max_parallel=int(max_parallel) if max_parallel is not None else None,
        detail_label=str(detail_label),
    )
