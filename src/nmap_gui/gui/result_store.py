"""Result storage and summary helpers for the GUI."""
from __future__ import annotations

import copy
from typing import Dict, List, Sequence

from ..models import HostScanResult, SafeScanReport
from ..result_grid import ResultGrid
from .summary_panel import SummaryPanel


class ResultStore:
    """Tracks HostScanResult objects and keeps the grid/summary in sync."""

    def __init__(self, result_grid: ResultGrid, summary_panel: SummaryPanel) -> None:
        self._result_grid = result_grid
        self._summary_panel = summary_panel
        self._results: List[HostScanResult] = []
        self._result_lookup: Dict[str, HostScanResult] = {}

    def reset(self, *, emit_selection_changed: bool = True) -> None:
        self._results.clear()
        self._result_lookup.clear()
        self._result_grid.reset(emit_signal=emit_selection_changed)

    def add_or_update(self, result: HostScanResult) -> HostScanResult:
        existing = self._result_lookup.get(result.target)
        if existing:
            self._merge(existing, result)
            self._result_grid.update_result(existing)
            return existing
        self._results.append(result)
        self._result_lookup[result.target] = result
        self._result_grid.update_result(result)
        return result

    def _merge(self, existing: HostScanResult, new_result: HostScanResult) -> None:
        existing.is_alive = new_result.is_alive
        existing.open_ports = list(new_result.open_ports)
        existing.os_guess = new_result.os_guess
        existing.os_accuracy = new_result.os_accuracy
        existing.high_ports = list(new_result.high_ports)
        existing.score_breakdown = dict(new_result.score_breakdown)
        existing.score = new_result.score
        existing.priority = new_result.priority
        existing.errors = list(new_result.errors)
        existing.detail_level = new_result.detail_level
        existing.detail_updated_at = new_result.detail_updated_at
        if new_result.diagnostics_report is not None:
            existing.diagnostics_report = new_result.diagnostics_report

    def set_diagnostics_status(self, target: str, status: str, timestamp: str) -> None:
        result = self._result_lookup.get(target)
        if not result:
            return
        result.diagnostics_status = status
        result.diagnostics_updated_at = timestamp
        self._result_grid.update_result(result, allow_sort_restore=False)

    def set_diagnostics_report(self, target: str, report: SafeScanReport) -> None:
        result = self._result_lookup.get(target)
        if not result:
            return
        result.diagnostics_report = report
        self._result_grid.update_result(result, allow_sort_restore=False)

    def diagnostics_report_for(self, target: str) -> SafeScanReport | None:
        result = self._result_lookup.get(target)
        if not result:
            return None
        return result.diagnostics_report

    def has_results(self) -> bool:
        return bool(self._results)

    def results(self) -> List[HostScanResult]:
        return self._results

    def snapshot_results(self) -> List[HostScanResult]:
        return copy.deepcopy(self._results)

    def restore_results(self, stored: Sequence[HostScanResult]) -> None:
        if not stored:
            return
        for item in stored:
            result = copy.deepcopy(item)
            self._results.append(result)
            self._result_lookup[result.target] = result
            self._result_grid.update_result(result, allow_sort_restore=False)

    def update_summary(self, *, target_count: int, requested_hosts: int, status: str) -> None:
        discovered = len(self._results)
        alive = sum(1 for result in self._results if result.is_alive)
        self._summary_panel.update_summary(
            target_count=target_count,
            requested_hosts=requested_hosts,
            discovered_hosts=discovered,
            alive_hosts=alive,
            status=status,
        )

    def export_payload(self) -> List[HostScanResult]:
        return self._results
