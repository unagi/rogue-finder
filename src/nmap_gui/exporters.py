"""Utilities for exporting scan results."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

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
]


def export_csv(path: str | Path, results: Iterable[HostScanResult]) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=EXPORT_FIELDS)
        writer.writeheader()
        for item in results:
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
                "errors": " | ".join(item.errors),
            }
            writer.writerow(row)
    return output


def export_json(path: str | Path, results: Iterable[HostScanResult]) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = [item.to_dict() for item in results]
    output.write_text(json.dumps(serialized, indent=2, ensure_ascii=False), encoding="utf-8")
    return output
