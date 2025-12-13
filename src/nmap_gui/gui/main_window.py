"""PySide6 GUI for the Nmap discovery & rating application."""
from __future__ import annotations

import ipaddress
import math
import sys
from datetime import datetime
from typing import List, Sequence, Set

from PySide6.QtCore import QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QFileDialog, QMainWindow, QMessageBox, QVBoxLayout, QWidget

from ..config import AppSettings, get_settings
from ..exporters import export_csv, export_json
from ..i18n import detect_language, format_error_list, format_error_record, translate
from ..job_eta import JobEtaController
from ..models import (
    ErrorRecord,
    HostScanResult,
    SafeScanReport,
    ScanConfig,
    ScanLogEvent,
    ScanMode,
    sanitize_targets,
)
from .result_grid import ResultGrid
from ..scan_manager import ScanManager
from ..state_store import AppState
from .config_editor import ConfigEditorDialog
from .export_toolbar import ExportToolbar
from .privileges import has_required_privileges, show_privileged_hint
from .result_store import ResultStore
from .safe_scan_controller import SafeScanController
from .safe_scan_report_viewer import SafeScanReportViewer
from .scan_controls import ScanControlsPanel, ScanControlsState
from .scan_log_dialog import ScanLogDialog
from .state_controller import StateController
from .summary_panel import SummaryPanel


class MainWindow(QMainWindow):
    """Primary top-level window."""

    def __init__(
        self,
        settings: AppSettings | None = None,
        state: AppState | None = None,
        app_icon: QIcon | None = None,
    ) -> None:
        super().__init__()
        self._settings = settings or get_settings()
        self._language = detect_language()
        self._priority_labels = {
            "High": translate("priority_high", self._language),
            "Medium": translate("priority_medium", self._language),
            "Low": translate("priority_low", self._language),
        }
        self.setWindowTitle(self._t("window_title"))
        if app_icon is not None and not app_icon.isNull():
            self.setWindowIcon(app_icon)
        self.resize(1000, 700)
        self._pending_scan_configs: List[ScanConfig] = []
        self._active_scan_kind: str | None = None
        self._current_scan_targets: List[str] = []
        self._controls = ScanControlsPanel(self._t, self)
        self._connect_control_signals()
        self._result_grid = ResultGrid(
            translator=self._t,
            language=self._language,
            priority_labels=self._priority_labels,
            priority_colors=self._settings.ui.priority_colors,
            parent=self,
        )
        self._result_grid.selectionChanged.connect(self._on_result_grid_selection_changed)
        self._result_grid.runAdvancedRequested.connect(self._on_run_advanced_clicked)
        self._result_grid.runSafetyRequested.connect(self._on_run_safety_clicked)
        self._result_grid.diagnosticsViewRequested.connect(self._on_diagnostics_view_requested)
        self._summary_panel = SummaryPanel(self._t, self)
        self._export_toolbar = ExportToolbar(self._t, self)
        self._export_toolbar.export_csv_requested.connect(self._export_csv)
        self._export_toolbar.export_json_requested.connect(self._export_json)
        self._report_viewer = SafeScanReportViewer(self._t, self._language, self)
        self._result_store = ResultStore(self._result_grid, self._summary_panel)
        self._scan_manager = ScanManager(self._settings)
        self._target_count = 0
        self._requested_host_estimate = 0
        self._summary_status = self._t("summary_status_idle")
        self._summary_has_error = False
        self._scan_active = False
        self._state_controller = StateController(self._t)
        self._state_controller.initialize(state)
        self._state_save_timer = QTimer(self)
        self._state_save_timer.setSingleShot(True)
        self._state_save_timer.setInterval(750)
        self._state_save_timer.timeout.connect(self._persist_state)
        self._log_dialog: ScanLogDialog | None = None
        self._config_editor: ConfigEditorDialog | None = None
        self._setup_scan_manager()
        self._build_ui()
        self._job_eta = JobEtaController(
            self,
            self.statusBar().showMessage,
            summary_callback=None,
        )
        self._safe_scan_controller = SafeScanController(
            settings=self._settings,
            translator=self._t,
            parent=self,
            job_eta=self._job_eta,
            status_callback=self.statusBar().showMessage,
            set_summary_state=self._set_summary_state,
            refresh_actions=self._refresh_action_buttons,
            is_scan_active=lambda: self._scan_active,
            set_diagnostics_status=self._set_diagnostics_status,
            clear_safety_selection=self._result_grid.clear_safety_selection_for_target,
            store_diagnostics_report=self._store_diagnostics_report,
            estimate_parallel_seconds=self._estimate_parallel_total_seconds,
        )
        self._state_controller.apply(
            window=self,
            controls=self._controls,
            result_store=self._result_store,
            result_grid=self._result_grid,
        )
        self._update_summary()
        self._update_mac_limited_label()
        self._controls.targets_changed.connect(self._on_form_state_changed)
        if not self._state_controller.prompt_storage_warnings(self):
            QTimer.singleShot(0, self.close)

    def _setup_scan_manager(self) -> None:
        self._scan_manager.started.connect(self._on_scan_started)
        self._scan_manager.progress.connect(self._on_progress)
        self._scan_manager.result_ready.connect(self._on_result)
        self._scan_manager.error.connect(self._on_error)
        self._scan_manager.finished.connect(self._on_finished)
        self._scan_manager.log_ready.connect(self._on_log_event)

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self._controls)
        layout.addWidget(self._result_grid.widget())
        layout.addWidget(self._summary_panel)
        layout.addWidget(self._export_toolbar)
        layout.setStretch(0, 0)
        layout.setStretch(1, 2)
        layout.setStretch(2, 0)
        layout.setStretch(3, 0)
        self.setCentralWidget(central)
        self.statusBar().showMessage(self._t("ready"))
        self._update_summary()

    def _estimate_requested_hosts(self, targets: Sequence[str]) -> int:
        total = 0
        for entry in targets:
            total += self._estimate_hosts_for_target(entry)
        return total

    def _estimate_hosts_for_target(self, target: str) -> int:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return 1
        return network.num_addresses

    def _update_summary(self) -> None:
        self._result_store.update_summary(
            target_count=self._target_count,
            requested_hosts=self._requested_host_estimate,
            status=self._summary_status,
        )

    def _set_summary_state(self, translation_key: str) -> None:
        self._summary_status = self._t(translation_key)
        self._update_summary()

    def _on_start_clicked(self) -> None:
        targets = list(dict.fromkeys(sanitize_targets(self._controls.targets_text())))
        if not targets:
            QMessageBox.warning(
                self,
                self._t("missing_targets_title"),
                self._t("missing_targets_body"),
            )
            return
        self._target_count = len(targets)
        self._requested_host_estimate = self._estimate_requested_hosts(targets)
        self._summary_has_error = False
        self._reset_result_storage(emit_selection_changed=False)
        self._result_grid.reset_progress(len(targets))
        self._set_summary_state("summary_status_scanning")
        config = ScanConfig(
            targets=targets,
            scan_modes={ScanMode.ICMP, ScanMode.PORTS},
            port_list=self._settings.scan.fast_port_scan_list,
            timeout_seconds=self._settings.scan.default_timeout_seconds,
            detail_label="fast",
        )
        self._pending_scan_configs = []
        self._active_scan_kind = "fast"
        self._current_scan_targets = list(targets)
        self._ensure_log_dialog(targets, show=False, reset=True)
        self._scan_manager.start(config)
        self._scan_active = True
        self._update_controls_state()
        self.statusBar().showMessage(
            self._t("fast_scan_running_status").format(
                count=self._target_count,
                hosts=self._requested_host_estimate,
            )
        )
        self._refresh_action_buttons()

    def _on_clear_results(self) -> None:
        if self._scan_active or self._safe_scan_controller.is_active():
            QMessageBox.information(
                self,
                self._t("clear_blocked_title"),
                self._t("clear_blocked_body"),
            )
            return
        if not self._result_store.has_results():
            return
        reply = QMessageBox.question(
            self,
            self._t("clear_results_title"),
            self._t("clear_results_body"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self._reset_result_storage()
        self._set_summary_state("summary_status_idle")
        self._on_form_state_changed()
        self._refresh_action_buttons()

    def _on_run_advanced_clicked(self, include_os: bool = False) -> None:
        if self._scan_active or self._safe_scan_controller.is_active():
            QMessageBox.information(
                self,
                self._t("advanced_blocked_title"),
                self._t("advanced_blocked_body"),
            )
            return
        advanced_targets = self._result_grid.advanced_targets()
        if not advanced_targets:
            QMessageBox.information(
                self,
                self._t("advanced_missing_title"),
                self._t("advanced_missing_body"),
            )
            return
        if include_os and not has_required_privileges({ScanMode.OS}):
            show_privileged_hint(self, self._t)
            return
        targets = sorted(advanced_targets)
        config = self._build_advanced_config(targets, include_os=include_os)
        self._pending_scan_configs = []
        self._active_scan_kind = "advanced"
        self._current_scan_targets = list(config.targets)
        self._scan_active = True
        self._update_controls_state()
        self.statusBar().showMessage(self._t("advanced_running_status"))
        self._set_summary_state("summary_status_advanced")
        self._announce_advanced_eta(len(config.targets))
        self._ensure_log_dialog(config.targets, show=False, reset=True)
        self._result_grid.reset_progress(len(config.targets))
        self._scan_manager.start(config)
        self._refresh_action_buttons()

    def _on_run_safety_clicked(self) -> None:
        if self._scan_active:
            QMessageBox.information(
                self,
                self._t("safe_scan_blocked_title"),
                self._t("safe_scan_blocked_body"),
            )
            return
        if self._safe_scan_controller.is_active() or self._safe_scan_controller.is_running():
            QMessageBox.information(
                self,
                self._t("safe_scan_running_title"),
                self._t("safe_scan_running_body"),
            )
            return
        safety_selection = self._result_grid.safety_targets()
        if not safety_selection:
            QMessageBox.information(
                self,
                self._t("safe_scan_missing_title"),
                self._t("safe_scan_missing_body"),
            )
            return
        targets = sorted(safety_selection)
        for target in targets:
            self._set_diagnostics_status(target, "running")
        self._safe_scan_controller.start(targets)

    def _on_show_log_clicked(self) -> None:
        if not self._log_dialog:
            return
        self._log_dialog.show()
        self._log_dialog.raise_()
        self._log_dialog.activateWindow()

    def _on_stop_clicked(self) -> None:
        self._scan_manager.stop()
        self._result_grid.finish_progress()
        self._pending_scan_configs.clear()
        self._active_scan_kind = None
        self._current_scan_targets = []
        self.statusBar().showMessage(self._t("scan_stopped"))
        self._scan_active = False
        self._set_summary_state("summary_status_stopped")
        self._job_eta.stop("advanced")
        self._refresh_action_buttons()
        if self._log_dialog:
            self._log_dialog.mark_scan_finished()

    def _on_scan_started(self, total: int) -> None:
        self._result_grid.reset_progress(total)

    def _on_progress(self, done: int, total: int) -> None:
        self._result_grid.set_progress(done, total)

    def _on_result(self, result: HostScanResult) -> None:
        if self._active_scan_kind == "advanced":
            self._handle_advanced_result(result)
        else:
            self._handle_fast_result(result)
        self._update_summary()
        self._on_form_state_changed()

    def _reset_result_storage(self, *, emit_selection_changed: bool = True) -> None:
        self._result_store.reset(emit_selection_changed=emit_selection_changed)
        self._update_mac_limited_label()
        self._report_viewer.close()

    def _on_result_grid_selection_changed(self) -> None:
        self._refresh_action_buttons()
        self._on_form_state_changed()

    def _set_diagnostics_status(self, target: str, status: str) -> None:
        timestamp = datetime.now().astimezone().isoformat()
        self._result_store.set_diagnostics_status(target, status, timestamp)

    def _store_diagnostics_report(self, report: SafeScanReport) -> None:
        self._result_store.set_diagnostics_report(report.target, report)
        should_show = (not self._report_viewer.isVisible()) or (
            self._report_viewer.current_target() == report.target
        )
        if should_show:
            self._report_viewer.show_report(report)

    def _on_diagnostics_view_requested(self, target: str) -> None:
        report = self._result_store.diagnostics_report_for(target)
        if report is None:
            QMessageBox.information(
                self,
                self._t("diagnostics_viewer_missing_title"),
                self._t("diagnostics_viewer_missing_body").format(target=target),
            )
            return
        self._report_viewer.show_report(report)

    def _update_controls_state(self) -> None:
        if self._safe_scan_controller.is_active():
            state = ScanControlsState.SAFE_RUNNING
        elif self._scan_active:
            state = ScanControlsState.SCANNING
        else:
            state = ScanControlsState.IDLE
        self._controls.set_state(state)

    def _refresh_action_buttons(self) -> None:
        advanced_allowed = (
            not self._scan_active and not self._safe_scan_controller.is_active() and self._result_grid.has_advanced_selection()
        )
        safety_allowed = (
            not self._scan_active and not self._safe_scan_controller.is_active() and self._result_grid.has_safety_selection()
        )
        self._result_grid.set_run_buttons_enabled(advanced=advanced_allowed, safety=safety_allowed)
        clear_allowed = not self._scan_active and not self._safe_scan_controller.is_active()
        self._controls.set_clear_enabled(clear_allowed)
        self._update_controls_state()

    def _update_mac_limited_label(self) -> None:
        limited = sys.platform == "darwin" and not has_required_privileges({ScanMode.OS})
        message = self._t("mac_limited_body")
        self._summary_panel.set_mac_limited(limited, message)
        self._result_grid.set_os_button_allowed(not limited, tooltip=message if limited else "")

    def _consume_placeholder_error(self, result: HostScanResult) -> bool:
        if not result.is_placeholder:
            return False
        details = "\n".join(format_error_list(result.errors, self._language))
        if not details:
            details = self._t("placeholder_error_detail_missing")
        QMessageBox.critical(
            self,
            self._t("placeholder_error_title").format(target=result.target),
            self._t("placeholder_error_body").format(details=details),
        )
        self._summary_has_error = True
        self._set_summary_state("placeholder_error_status")
        return True

    def _handle_fast_result(self, result: HostScanResult) -> None:
        if self._consume_placeholder_error(result):
            return
        self._result_store.add_or_update(result)

    def _handle_advanced_result(self, result: HostScanResult) -> None:
        if self._consume_placeholder_error(result):
            return
        self._result_store.add_or_update(result)

    def _announce_advanced_eta(self, target_count: int) -> None:
        eta_seconds = self._estimate_parallel_total_seconds(
            target_count,
            float(self._settings.scan.advanced_timeout_seconds),
            timeout_seconds=float(self._settings.scan.advanced_timeout_seconds),
            parallelism=self._settings.scan.advanced_max_parallel,
        )
        self._job_eta.start(
            kind="advanced",
            expected_seconds=eta_seconds,
            message_builder=self._build_advanced_eta_message,
        )

    def _build_advanced_eta_message(self, remaining: float) -> str:
        eta_text = self._format_eta_seconds(remaining)
        return self._t("advanced_running_status_eta").format(eta=eta_text)

    def _build_advanced_config(self, targets: Sequence[str], *, include_os: bool) -> ScanConfig:
        modes: Set[ScanMode] = {ScanMode.PORTS}
        if include_os:
            modes.add(ScanMode.OS)
        return ScanConfig(
            targets=tuple(targets),
            scan_modes=modes,
            port_list=self._settings.scan.port_scan_list,
            timeout_seconds=self._settings.scan.advanced_timeout_seconds,
            max_parallel=self._settings.scan.advanced_max_parallel,
            detail_label="advanced",
        )

    def _format_eta_seconds(self, seconds: float) -> str:
        total = max(int(round(seconds)), 0)
        mins, secs = divmod(total, 60)
        hours, mins = divmod(mins, 60)
        if hours:
            return f"{hours:d}:{mins:02d}:{secs:02d}"
        return f"{mins:02d}:{secs:02d}"

    def _estimate_parallel_total_seconds(
        self,
        job_count: int,
        per_job_seconds: float,
        *,
        timeout_seconds: float,
        parallelism: int,
    ) -> float:
        if job_count <= 0:
            return 0.0
        per_job = max(0.0, min(per_job_seconds, timeout_seconds))
        slots = max(1, parallelism)
        batches = math.ceil(job_count / slots)
        return per_job * batches




    def _on_error(self, payload) -> None:
        if isinstance(payload, ErrorRecord):
            message = format_error_record(payload, self._language)
        else:
            message = str(payload)
        QMessageBox.critical(self, self._t("scan_error_title"), message)
        self.statusBar().showMessage(message)
        self._summary_has_error = True
        self._set_summary_state("summary_status_error")
        self._job_eta.stop("advanced")
        self._result_grid.finish_progress()
        if self._log_dialog:
            self._log_dialog.mark_scan_finished()

    def _on_finished(self) -> None:
        completed_targets = list(self._current_scan_targets)
        if self._active_scan_kind == "advanced" and completed_targets:
            self._result_grid.clear_completed_advanced_selection(completed_targets)
        if self._active_scan_kind == "advanced" and self._pending_scan_configs:
            next_config = self._pending_scan_configs.pop(0)
            self._current_scan_targets = list(next_config.targets)
            self._announce_advanced_eta(len(next_config.targets))
            self._ensure_log_dialog(next_config.targets, show=False, reset=True)
            self._result_grid.reset_progress(len(next_config.targets))
            self._scan_manager.start(next_config)
            return
        self._result_grid.finish_progress()
        self._job_eta.stop("advanced")
        self._scan_active = False
        self._pending_scan_configs.clear()
        self._active_scan_kind = None
        self._current_scan_targets = []
        self.statusBar().showMessage(self._t("scan_finished"))
        if not self._summary_has_error:
            if self._result_store.has_results():
                self._set_summary_state("summary_status_finished")
            else:
                self._set_summary_state("summary_status_no_hosts")
        else:
            self._update_summary()
        self._refresh_action_buttons()
        if self._log_dialog:
            self._log_dialog.mark_scan_finished()

    def _t(self, key: str) -> str:
        return translate(key, self._language)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._scan_manager.stop()
        self._safe_scan_controller.stop()
        if self._log_dialog:
            self._log_dialog.deleteLater()
            self._log_dialog = None
        self._controls.set_log_enabled(False)
        self._state_save_timer.stop()
        if not self._persist_state(on_close=True):
            event.ignore()
            return
        super().closeEvent(event)

    def _export_csv(self) -> None:
        if not self._result_store.has_results():
            QMessageBox.information(
                self,
                self._t("no_results_title"),
                self._t("no_results_body"),
            )
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._t("export_csv_dialog"),
            "scan_results.csv",
            self._t("export_csv_filter"),
        )
        if not path:
            return
        export_csv(path, self._result_store.export_payload(), language=self._language)
        self.statusBar().showMessage(self._t("export_csv_done").format(path=path))

    def _export_json(self) -> None:
        if not self._result_store.has_results():
            QMessageBox.information(
                self,
                self._t("no_results_title"),
                self._t("no_results_body"),
            )
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._t("export_json_dialog"),
            "scan_results.json",
            self._t("export_json_filter"),
        )
        if not path:
            return
        export_json(path, self._result_store.export_payload(), language=self._language)
        self.statusBar().showMessage(self._t("export_json_done").format(path=path))

    def _on_form_state_changed(self, *_args) -> None:
        if not self._state_controller.persistence_enabled():
            return
        self._state_save_timer.start()

    def _persist_state(self, *, on_close: bool = False) -> bool:
        return self._state_controller.persist(
            window=self,
            controls=self._controls,
            result_store=self._result_store,
            result_grid=self._result_grid,
            on_close=on_close,
        )

    def _ensure_log_dialog(self, targets: Sequence[str], *, show: bool, reset: bool = True) -> None:
        if self._log_dialog is None:
            self._log_dialog = ScanLogDialog(self, self._language)
            self._log_dialog.destroyed.connect(self._on_log_dialog_destroyed)
        if reset:
            self._log_dialog.reset()
        if targets:
            self._log_dialog.set_initial_targets(targets)
        if show:
            self._log_dialog.show()
            self._log_dialog.raise_()
            self._log_dialog.activateWindow()
        self._controls.set_log_enabled(True)

    def _on_log_dialog_destroyed(self, _obj=None) -> None:
        self._log_dialog = None
        self._controls.set_log_enabled(False)

    def _on_log_event(self, event: ScanLogEvent) -> None:
        if not isinstance(event, ScanLogEvent):
            return
        if self._log_dialog:
            self._log_dialog.append_event(event)

    def _connect_control_signals(self) -> None:
        self._controls.start_requested.connect(self._on_start_clicked)
        self._controls.stop_requested.connect(self._on_stop_clicked)
        self._controls.clear_requested.connect(self._on_clear_results)
        self._controls.log_requested.connect(self._on_show_log_clicked)
        self._controls.config_editor_requested.connect(self._on_edit_config_requested)

    def _on_edit_config_requested(self) -> None:
        if self._scan_active or self._safe_scan_controller.is_active():
            QMessageBox.information(
                self,
                self._t("config_editor_blocked_title"),
                self._t("config_editor_blocked_body"),
            )
            return
        if self._config_editor is None:
            self._config_editor = ConfigEditorDialog(self._t, self)
            self._config_editor.settingsUpdated.connect(self._apply_updated_settings)
            self._config_editor.destroyed.connect(self._on_config_editor_destroyed)
        self._config_editor.reload_from_disk()
        self._config_editor.show()
        self._config_editor.raise_()
        self._config_editor.activateWindow()

    def _on_config_editor_destroyed(self, _obj=None) -> None:
        self._config_editor = None

    def _apply_updated_settings(self, settings: AppSettings) -> None:
        self._settings = settings
        self._scan_manager.update_settings(settings)
        self._safe_scan_controller.update_settings(settings)
        self._result_grid.update_priority_colors(settings.ui.priority_colors)
        self._update_mac_limited_label()
        self.statusBar().showMessage(self._t("config_editor_status_applied"))
