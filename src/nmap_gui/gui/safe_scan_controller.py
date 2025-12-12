"""Safe scan orchestration helper."""
from __future__ import annotations

import time
from typing import Callable, List, Sequence

from PySide6.QtWidgets import QMessageBox, QWidget

from ..config import AppSettings
from ..job_eta import JobEtaController
from ..models import SafeScanReport
from ..scan_manager import SafeScriptManager

Translator = Callable[[str], str]


class SafeScanController:
    """Owns safe-scan lifecycle, ETA tracking, and dialogs."""

    def __init__(
        self,
        *,
        settings: AppSettings,
        translator: Translator,
        parent: QWidget,
        job_eta: JobEtaController,
        status_callback: Callable[[str], None],
        set_summary_message: Callable[[str], None],
        refresh_actions: Callable[[], None],
        is_scan_active: Callable[[], bool],
        set_diagnostics_status: Callable[[str, str], None],
        clear_safety_selection: Callable[[str], None],
        dialog_factory: Callable[[SafeScanReport], QWidget],
        estimate_parallel_seconds: Callable[[int, float, float, int], float],
    ) -> None:
        self._settings = settings
        self._translator = translator
        self._parent = parent
        self._job_eta = job_eta
        self._status_callback = status_callback
        self._set_summary_message = set_summary_message
        self._refresh_actions = refresh_actions
        self._is_scan_active = is_scan_active
        self._set_diagnostics_status = set_diagnostics_status
        self._clear_safety_selection = clear_safety_selection
        self._dialog_factory = dialog_factory
        self._estimate_parallel = estimate_parallel_seconds

        self._manager = SafeScriptManager(self._settings)
        self._manager.started.connect(self._on_started)
        self._manager.progress.connect(self._on_progress)
        self._manager.result_ready.connect(self._on_result)
        self._manager.error.connect(self._on_error)
        self._manager.finished.connect(self._on_finished)

        self._active = False
        self._history: List[float] = []
        self._expected_duration = float(self._settings.safe_scan.default_duration_seconds)
        self._elapsed_start: float | None = None
        self._batch_total = 0
        self._completed = 0
        self._parallel = max(1, self._settings.safe_scan.max_parallel)

    def is_active(self) -> bool:
        return self._active

    def is_running(self) -> bool:
        return self._manager.is_running()

    def start(self, targets: Sequence[str]) -> None:
        self._manager.start(targets)

    def stop(self) -> None:
        self._manager.stop()

    def _record_duration(self, duration: float) -> None:
        if duration <= 0:
            return
        self._history.append(duration)
        if len(self._history) > self._settings.safe_scan.history_limit:
            self._history.pop(0)
        average = sum(self._history) / len(self._history)
        timeout = float(self._settings.safe_scan.timeout_seconds)
        baseline = float(self._settings.safe_scan.default_duration_seconds)
        self._expected_duration = min(timeout, max(baseline, average))

    def _on_started(self, total: int) -> None:
        self._active = True
        self._batch_total = total
        self._completed = 0
        self._elapsed_start = time.monotonic()
        self._refresh_actions()
        per_host = max(self._expected_duration, 1.0)
        expected = self._estimate_parallel(
            total,
            per_host,
            timeout_seconds=float(self._settings.safe_scan.timeout_seconds),
            parallelism=self._parallel,
        )
        self._job_eta.start(
            kind="safe",
            expected_seconds=expected,
            message_builder=self._build_eta_message,
        )

    def _on_progress(self, done: int, total: int) -> None:
        self._completed = done
        self._batch_total = total
        self._job_eta.refresh("safe")

    def _on_result(self, report: SafeScanReport) -> None:
        status = "completed" if report.success else "failed"
        self._set_diagnostics_status(report.target, status)
        self._clear_safety_selection(report.target)
        dialog = self._dialog_factory(report)
        dialog.exec()
        if getattr(dialog, "saved_path", None):
            self._status_callback(
                self._translator("safe_scan_save_success_body").format(path=dialog.saved_path)
            )
        self._record_duration(report.duration_seconds)
        self._refresh_actions()

    def _on_error(self, payload) -> None:
        message = str(payload)
        QMessageBox.critical(
            self._parent,
            self._translator("safe_scan_error_title"),
            self._translator("safe_scan_error_body").format(message=message),
        )
        self._status_callback(message)
        self._set_summary_message(message)
        self._job_eta.stop("safe")

    def _on_finished(self) -> None:
        duration: float | None = None
        if self._elapsed_start is not None:
            duration = time.monotonic() - self._elapsed_start
        completed_total = self._batch_total
        self._active = False
        self._refresh_actions()
        self._job_eta.stop("safe")
        self._elapsed_start = None
        self._batch_total = 0
        self._completed = 0
        if not self._is_scan_active():
            if duration is not None and duration > 0:
                finished_message = self._translator("safe_scan_progress_complete_multi").format(
                    seconds=int(round(duration)),
                    total=max(completed_total, 1),
                )
            else:
                finished_message = self._translator("safe_scan_progress_finished")
            self._status_callback(finished_message)
            self._set_summary_message(finished_message)

    def _build_eta_message(self, remaining: float) -> str:
        total = max(self._batch_total, 1)
        done = min(self._completed, total)
        eta = max(int(round(remaining)), 0)
        mins, secs = divmod(eta, 60)
        hours, mins = divmod(mins, 60)
        eta_text = f"{hours:d}:{mins:02d}:{secs:02d}" if hours else f"{mins:02d}:{secs:02d}"
        return self._translator("safe_scan_progress_running_multi").format(
            done=done,
            total=total,
            eta=eta_text,
        )
