"""Shared helpers for formatting SafeScanReport content."""
from __future__ import annotations

from typing import List

from ..i18n import format_error_record, translate
from ..models import SafeScanReport
from ..utils import slugify_filename_component


def build_status_text(report: SafeScanReport, language: str) -> str:
    status_key = "safe_scan_status_success" if report.success else "safe_scan_status_failure"
    status_value = translate(status_key, language)
    return translate("safe_scan_status_label", language).format(status=status_value)


def build_report_text(report: SafeScanReport, language: str) -> str:
    lines: List[str] = []
    lines.append(f"{_label('safe_scan_label_target', language)}: {report.target}")
    lines.append(f"{_label('safe_scan_label_command', language)}: {report.command}")
    lines.append(
        f"{_label('safe_scan_label_started', language)}: {report.started_at.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}"
    )
    lines.append(
        f"{_label('safe_scan_label_finished', language)}: {report.finished_at.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}"
    )
    lines.append(f"{_label('safe_scan_label_duration', language)}: {report.duration_seconds:.1f}s")
    exit_code = (
        str(report.exit_code) if report.exit_code is not None else _label("safe_scan_label_none", language)
    )
    lines.append(f"{_label('safe_scan_label_exit_code', language)}: {exit_code}")
    lines.append(f"{_label('safe_scan_label_errors', language)}: ")
    if report.errors:
        for error in report.errors:
            lines.append(f"  - {format_error_record(error, language)}")
    else:
        lines.append(f"  {_label('safe_scan_label_none', language)}")
    lines.append("")
    lines.append(f"{_label('safe_scan_section_stdout', language)}: ")
    stdout_text = report.stdout.rstrip() or _label("safe_scan_section_empty", language)
    lines.append(stdout_text)
    lines.append("")
    lines.append(f"{_label('safe_scan_section_stderr', language)}: ")
    stderr_text = report.stderr.rstrip() or _label("safe_scan_section_empty", language)
    lines.append(stderr_text)
    return "\n".join(lines)


def build_default_filename(report: SafeScanReport) -> str:
    timestamp = report.finished_at.astimezone().strftime("%Y%m%d-%H%M%S")
    target_slug = slugify_filename_component(report.target, fallback="target")
    return f"safe-scan_{target_slug}_{timestamp}.txt"


def _label(key: str, language: str) -> str:
    return translate(key, language)
