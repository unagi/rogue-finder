"""Utilities for exporting scan results."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .i18n import detect_language, format_error_list
from .models import HostScanResult

EXPORT_FIELDS = [
    "target",
    "is_alive",
    "open_ports",
    "os_guess",
    "os_accuracy",
    "high_ports",
    "score",
    "priority",
    "score_breakdown",
    "errors",
    "detail_level",
    "detail_updated_at",
]


def export_csv(
    path: str | Path,
    results: Iterable[HostScanResult],
    *,
    language: str | None = None,
) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    lang = language or detect_language()
    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=EXPORT_FIELDS)
        writer.writeheader()
        for item in results:
            formatted_errors = " | ".join(format_error_list(item.errors, lang))
            row = {
                "target": item.target,
                "is_alive": item.is_alive,
                "open_ports": ",".join(str(p) for p in item.open_ports),
                "os_guess": item.os_guess,
                "os_accuracy": item.os_accuracy if item.os_accuracy is not None else "",
                "high_ports": ",".join(str(p) for p in item.high_ports),
                "score": item.score,
                "priority": item.priority,
                "score_breakdown": json.dumps(item.score_breakdown, ensure_ascii=False),
                "errors": formatted_errors,
                "detail_level": item.detail_level,
                "detail_updated_at": item.detail_updated_at or "",
            }
            writer.writerow(row)
    return output


def export_json(
    path: str | Path,
    results: Iterable[HostScanResult],
    *,
    language: str | None = None,
) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    lang = language or detect_language()
    serialized = []
    for item in results:
        payload = item.to_dict()
        payload["errors_text"] = format_error_list(item.errors, lang)
        payload.pop("diagnostics_status", None)
        payload.pop("diagnostics_updated_at", None)
        serialized.append(payload)
    output.write_text(json.dumps(serialized, indent=2, ensure_ascii=False), encoding="utf-8")
    return output
