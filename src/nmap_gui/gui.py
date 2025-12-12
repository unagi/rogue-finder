"""PySide6 GUI for the Nmap discovery & rating application."""
from __future__ import annotations

import copy
import ipaddress
import math
import os
import shlex
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Sequence, Set

from PySide6.QtCore import QByteArray, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .config import AppSettings, get_settings
from .exporters import export_csv, export_json
from .i18n import detect_language, format_error_list, format_error_record, translate
from .job_eta import JobEtaController
from .result_grid import ResultGrid
from .models import (
    ErrorRecord,
    HostScanResult,
    SafeScanReport,
    ScanConfig,
    ScanLogEvent,
    ScanMode,
    sanitize_targets,
)
from .scan_manager import SafeScriptManager, ScanManager
from .state_store import AppState, load_state, save_state
from .storage_warnings import StorageWarning, consume_storage_warnings
from .utils import slugify_filename_component


class SafeScanDialog(QDialog):
    """Modal dialog that shows the safe script report and enables exporting."""

    def __init__(self, parent: QWidget, report: SafeScanReport, language: str):
        super().__init__(parent)
        self._report = report
        self._language = language
        self.saved_path: str | None = None
        self._report_text = self._build_report_text()
        self.setWindowTitle(
            translate("safe_scan_dialog_title", language).format(target=report.target)
        )
        layout = QVBoxLayout(self)
        self._status_label = QLabel(self._build_status_text())
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)
        self._text_edit = QPlainTextEdit()
        self._text_edit.setReadOnly(True)
        self._text_edit.setPlainText(self._report_text)
        layout.addWidget(self._text_edit)
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        save_button = button_box.addButton(
            translate("safe_scan_save_button", language),
            QDialogButtonBox.ActionRole,
        )
        save_button.clicked.connect(self._save_report)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _build_status_text(self) -> str:
        status_key = "safe_scan_status_success" if self._report.success else "safe_scan_status_failure"
        status_value = translate(status_key, self._language)
        return translate("safe_scan_status_label", self._language).format(status=status_value)

    def _build_report_text(self) -> str:
        lines: List[str] = []
        lines.append(f"{self._label('safe_scan_label_target')}: {self._report.target}")
        lines.append(f"{self._label('safe_scan_label_command')}: {self._report.command}")
        lines.append(
            f"{self._label('safe_scan_label_started')}: {self._format_timestamp(self._report.started_at)}"
        )
        lines.append(
            f"{self._label('safe_scan_label_finished')}: {self._format_timestamp(self._report.finished_at)}"
        )
        lines.append(
            f"{self._label('safe_scan_label_duration')}: {self._report.duration_seconds:.1f}s"
        )
        exit_code = (
            str(self._report.exit_code)
            if self._report.exit_code is not None
            else self._label("safe_scan_label_none")
        )
        lines.append(f"{self._label('safe_scan_label_exit_code')}: {exit_code}")
        lines.append(f"{self._label('safe_scan_label_errors')}: ")
        if self._report.errors:
            for error in self._report.errors:
                lines.append(f"  - {format_error_record(error, self._language)}")
        else:
            lines.append(f"  {self._label('safe_scan_label_none')}")
        lines.append("")
        lines.append(f"{self._label('safe_scan_section_stdout')}: ")
        stdout_text = self._report.stdout.rstrip() or self._label("safe_scan_section_empty")
        lines.append(stdout_text)
        lines.append("")
        lines.append(f"{self._label('safe_scan_section_stderr')}: ")
        stderr_text = self._report.stderr.rstrip() or self._label("safe_scan_section_empty")
        lines.append(stderr_text)
        return "\n".join(lines)

    def _save_report(self) -> None:
        suggested_name = self._default_filename()
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._label("safe_scan_save_dialog"),
            suggested_name,
            self._label("safe_scan_save_filter"),
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self._report_text)
        self.saved_path = path
        QMessageBox.information(
            self,
            self._label("safe_scan_save_success_title"),
            self._label("safe_scan_save_success_body").format(path=path),
        )

    def _default_filename(self) -> str:
        timestamp = self._report.finished_at.astimezone().strftime("%Y%m%d-%H%M%S")
        target_slug = slugify_filename_component(self._report.target, fallback="target")
        return f"safe-scan_{target_slug}_{timestamp}.txt"

    def _label(self, key: str) -> str:
        return translate(key, self._language)

    def _format_timestamp(self, value: datetime) -> str:
        local_time = value.astimezone()
        return local_time.strftime("%Y-%m-%d %H:%M:%S %Z")


class ScanLogDialog(QDialog):
    """Modeless dialog that renders streaming stdout/stderr for discovery scans."""

    def __init__(self, parent: QWidget, language: str):
        super().__init__(parent)
        self._language = language
        self._logs: Dict[str, List[str]] = {}
        self._current_target: str | None = None
        self.setWindowTitle(translate("log_dialog_title", language))
        self.setModal(False)
        self.setMinimumSize(760, 420)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(QLabel(self._t("log_dialog_target_label")))
        self._target_combo = QComboBox()
        self._target_combo.currentTextChanged.connect(self._on_target_changed)
        top.addWidget(self._target_combo, 1)
        self._status_label = QLabel(self._t("log_dialog_status_idle"))
        self._status_label.setWordWrap(True)
        top.addWidget(self._status_label, 2)
        layout.addLayout(top)

        self._log_view = QPlainTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setPlaceholderText(self._t("log_dialog_placeholder"))
        layout.addWidget(self._log_view)

        button_box = QDialogButtonBox()
        self._copy_button = button_box.addButton(
            self._t("log_dialog_copy"), QDialogButtonBox.ButtonRole.ActionRole
        )
        self._copy_button.clicked.connect(self._copy_current_log)
        self._copy_button.setEnabled(False)
        self._save_button = button_box.addButton(
            self._t("log_dialog_save"), QDialogButtonBox.ButtonRole.ActionRole
        )
        self._save_button.clicked.connect(self._save_current_log)
        self._save_button.setEnabled(False)
        close_button = button_box.addButton(QDialogButtonBox.StandardButton.Close)
        close_button.clicked.connect(self.close)
        layout.addWidget(button_box)

    def set_initial_targets(self, targets: Sequence[str]) -> None:
        for target in targets:
            self._ensure_target_entry(target)
        if self._current_target is None and targets:
            self._set_current_target(targets[0])

    def append_event(self, event: ScanLogEvent) -> None:
        target = event.target
        self._ensure_target_entry(target)
        formatted = self._format_event(event)
        self._logs[target].append(formatted)
        if self._current_target is None:
            self._set_current_target(target)
        if self._current_target == target:
            self._log_view.appendPlainText(formatted)
            self._scroll_to_end()
        self._copy_button.setEnabled(True)
        self._save_button.setEnabled(True)
        self._status_label.setText(
            self._t("log_dialog_running").format(target=target, phase=self._phase_label(event.phase))
        )

    def mark_scan_finished(self) -> None:
        self._status_label.setText(self._t("log_dialog_finished"))
        self._copy_button.setEnabled(bool(self._logs))
        self._save_button.setEnabled(bool(self._logs))

    def reset(self) -> None:
        self._logs.clear()
        self._target_combo.clear()
        self._current_target = None
        self._log_view.clear()
        self._status_label.setText(self._t("log_dialog_status_idle"))
        self._copy_button.setEnabled(False)
        self._save_button.setEnabled(False)

    def _ensure_target_entry(self, target: str) -> None:
        if target in self._logs:
            return
        self._logs[target] = []
        if self._target_combo.findText(target) == -1:
            self._target_combo.addItem(target)

    def _set_current_target(self, target: str) -> None:
        index = self._target_combo.findText(target)
        if index >= 0:
            self._target_combo.setCurrentIndex(index)
        self._current_target = target
        self._refresh_log_view()

    def _on_target_changed(self, value: str) -> None:
        self._current_target = value or None
        self._refresh_log_view()
        if self._current_target:
            self._status_label.setText(
                self._t("log_dialog_running").format(
                    target=self._current_target,
                    phase=self._phase_label(None),
                )
            )
        else:
            self._status_label.setText(self._t("log_dialog_status_idle"))

    def _refresh_log_view(self) -> None:
        if not self._current_target:
            self._log_view.clear()
            return
        lines = self._logs.get(self._current_target, [])
        self._log_view.setPlainText("\n".join(lines))
        self._scroll_to_end()

    def _scroll_to_end(self) -> None:
        scrollbar = self._log_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _copy_current_log(self) -> None:
        text = self._current_log_text()
        if not text:
            return
        QApplication.clipboard().setText(text)
        self._status_label.setText(self._t("log_dialog_copy_done"))

    def _save_current_log(self) -> None:
        text = self._current_log_text()
        if not text:
            QMessageBox.information(
                self,
                self.windowTitle(),
                self._t("log_dialog_no_target"),
            )
            return
        target = self._current_target or "session"
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"scan-log_{slugify_filename_component(target, fallback='target')}_{timestamp}.txt"
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._t("log_dialog_save_dialog"),
            filename,
            self._t("log_dialog_save_filter"),
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
        except OSError as exc:
            QMessageBox.critical(
                self,
                self.windowTitle(),
                self._t("log_dialog_save_error").format(message=str(exc)),
            )
            return
        self._status_label.setText(self._t("log_dialog_save_success").format(path=path))

    def _current_log_text(self) -> str:
        if not self._current_target:
            return ""
        return "\n".join(self._logs.get(self._current_target, []))

    def _format_event(self, event: ScanLogEvent) -> str:
        timestamp = event.timestamp.astimezone().strftime("%H:%M:%S")
        phase_label = self._phase_label(event.phase)
        stream_label = self._stream_label(event.stream)
        return f"[{timestamp}] [{phase_label}] [{stream_label}] {event.line}"

    def _phase_label(self, phase: ScanMode | None) -> str:
        if phase == ScanMode.ICMP:
            return self._t("label_icmp")
        if phase == ScanMode.PORTS:
            return self._t("label_ports")
        if phase == ScanMode.OS:
            return self._t("label_os")
        return "-"

    def _stream_label(self, stream: str) -> str:
        mapping = {
            "stdout": self._t("log_dialog_stream_stdout"),
            "stderr": self._t("log_dialog_stream_stderr"),
            "info": self._t("log_dialog_stream_info"),
        }
        return mapping.get(stream, stream or "-")

    def _t(self, key: str) -> str:
        return translate(key, self._language)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        """Hide instead of destroying so MainWindow can re-open the dialog."""
        event.ignore()
        self.hide()


class MainWindow(QMainWindow):
    """Primary top-level window."""

    def __init__(self, settings: AppSettings | None = None, state: AppState | None = None) -> None:
        super().__init__()
        self._settings = settings or get_settings()
        self._language = detect_language()
        self._priority_labels = {
            "High": translate("priority_high", self._language),
            "Medium": translate("priority_medium", self._language),
            "Low": translate("priority_low", self._language),
        }
        self.setWindowTitle(self._t("window_title"))
        self.resize(1000, 700)
        self._results: List[HostScanResult] = []
        self._result_lookup: Dict[str, HostScanResult] = {}
        self._pending_scan_configs: List[ScanConfig] = []
        self._active_scan_kind: str | None = None
        self._current_scan_targets: List[str] = []
        self.log_button: QPushButton | None = None
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
        self._scan_manager = ScanManager(self._settings)
        self._safe_scan_manager = SafeScriptManager(self._settings)
        self.summary_label: QLabel | None = None
        self._target_count = 0
        self._requested_host_estimate = 0
        self._summary_status = self._t("summary_status_idle")
        self._summary_has_error = False
        self._safe_scan_active = False
        self._scan_active = False
        self._safe_scan_expected_duration = float(self._settings.safe_scan.default_duration_seconds)
        self._safe_scan_history: List[float] = []
        self._safe_scan_elapsed_start: float | None = None
        self._safe_scan_targets: List[str] = []
        self._safe_scan_batch_total = 0
        self._safe_scan_completed = 0
        self._safe_scan_parallel = max(1, self._settings.safe_scan.max_parallel)
        self._state_save_timer = QTimer(self)
        self._state_save_timer.setSingleShot(True)
        self._state_save_timer.setInterval(750)
        self._state_save_timer.timeout.connect(self._persist_state)
        self._log_dialog: ScanLogDialog | None = None
        self._disable_state_persistence = False
        self._app_state = self._initialize_state(state)
        self._setup_scan_manager()
        self._setup_safe_scan_manager()
        self._build_ui()
        self._job_eta = JobEtaController(
            self,
            self.statusBar().showMessage,
            self._set_summary_message,
        )
        self._apply_state_to_widgets()
        self._update_mac_limited_label()
        self._connect_state_change_signals()
        if not self._prompt_storage_warnings():
            QTimer.singleShot(0, self.close)

    def _setup_scan_manager(self) -> None:
        self._scan_manager.started.connect(self._on_scan_started)
        self._scan_manager.progress.connect(self._on_progress)
        self._scan_manager.result_ready.connect(self._on_result)
        self._scan_manager.error.connect(self._on_error)
        self._scan_manager.finished.connect(self._on_finished)
        self._scan_manager.log_ready.connect(self._on_log_event)

    def _setup_safe_scan_manager(self) -> None:
        self._safe_scan_manager.started.connect(self._on_safe_scan_started)
        self._safe_scan_manager.progress.connect(self._on_safe_scan_progress)
        self._safe_scan_manager.result_ready.connect(self._on_safe_scan_result)
        self._safe_scan_manager.error.connect(self._on_safe_scan_error)
        self._safe_scan_manager.finished.connect(self._on_safe_scan_finished)

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self._create_settings_panel())
        layout.addWidget(self._result_grid.widget())
        layout.addWidget(self._create_summary_panel())
        layout.addLayout(self._create_export_bar())
        self.setCentralWidget(central)
        self.statusBar().showMessage(self._t("ready"))
        self._update_summary()

    def _create_settings_panel(self) -> QWidget:
        group = QGroupBox(self._t("scan_settings"))
        grid = QGridLayout(group)
        grid.setContentsMargins(12, 12, 12, 8)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)

        grid.addWidget(QLabel(self._t("targets_label")), 0, 0)
        self.target_input = QPlainTextEdit()
        self.target_input.setPlaceholderText(self._t("targets_placeholder"))
        self.target_input.setFixedHeight(64)
        self.target_input.document().setDocumentMargin(4)
        grid.addWidget(self.target_input, 1, 0, 1, 4)

        self.start_button = QPushButton(self._t("fast_scan_button"))
        self.stop_button = QPushButton(self._t("stop"))
        self.stop_button.setEnabled(False)
        self.clear_button = QPushButton(self._t("clear_results_button"))
        self.log_button = QPushButton(self._t("open_log_button"))
        self.log_button.setEnabled(False)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)

        self.start_button.clicked.connect(self._on_start_clicked)
        self.stop_button.clicked.connect(self._on_stop_clicked)
        self.clear_button.clicked.connect(self._on_clear_results)
        self.log_button.clicked.connect(self._on_show_log_clicked)

        grid.addWidget(self.start_button, 2, 0)
        grid.addWidget(self.stop_button, 2, 1)
        grid.addWidget(self.clear_button, 2, 2)
        grid.addWidget(self.log_button, 2, 3)
        grid.addWidget(self.progress_bar, 3, 0, 1, 4)

        return group

    def _create_summary_panel(self) -> QWidget:
        group = QGroupBox(self._t("summary_title"))
        layout = QVBoxLayout(group)
        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)
        self.mac_limited_label = QLabel("")
        self.mac_limited_label.setWordWrap(True)
        font = self.mac_limited_label.font()
        font.setItalic(True)
        self.mac_limited_label.setFont(font)
        self.mac_limited_label.setVisible(False)
        layout.addWidget(self.mac_limited_label)
        return group

    def _create_export_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.addStretch()
        export_csv_btn = QPushButton(self._t("export_csv"))
        export_json_btn = QPushButton(self._t("export_json"))
        export_csv_btn.clicked.connect(self._export_csv)
        export_json_btn.clicked.connect(self._export_json)
        bar.addWidget(export_csv_btn)
        bar.addWidget(export_json_btn)
        return bar

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
        if not self.summary_label:
            return
        discovered = len(self._results)
        alive = sum(1 for result in self._results if result.is_alive)
        summary_text = self._t("summary_template").format(
            targets=self._target_count,
            requested=self._requested_host_estimate,
            discovered=discovered,
            alive=alive,
            status=self._summary_status,
        )
        self.summary_label.setText(summary_text)

    def _set_summary_message(self, message: str) -> None:
        self._summary_status = message
        self._update_summary()

    def _on_start_clicked(self) -> None:
        targets = sanitize_targets(self.target_input.toPlainText())
        if not targets:
            QMessageBox.warning(
                self,
                self._t("missing_targets_title"),
                self._t("missing_targets_body"),
            )
            return
        self._target_count = len(targets)
        self._requested_host_estimate = self._estimate_requested_hosts(targets)
        self._summary_status = self._t("scanning")
        self._summary_has_error = False
        self._reset_result_storage(emit_selection_changed=False)
        self._update_summary()
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
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.statusBar().showMessage(self._t("scanning"))
        self._refresh_action_buttons()

    def _on_clear_results(self) -> None:
        if self._scan_active or self._safe_scan_active:
            QMessageBox.information(
                self,
                self._t("clear_blocked_title"),
                self._t("clear_blocked_body"),
            )
            return
        if not self._results:
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
        self._update_summary()
        self._on_form_state_changed()
        self._refresh_action_buttons()

    def _on_run_advanced_clicked(self) -> None:
        if self._scan_active or self._safe_scan_active:
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
        os_selection = self._result_grid.os_targets()
        os_targets = sorted(os_selection)
        base_targets = sorted(advanced_targets - os_selection)
        configs: List[ScanConfig] = []
        if base_targets:
            configs.append(self._build_advanced_config(base_targets, include_os=False))
        if os_targets:
            if not self._has_required_privileges({ScanMode.OS}):
                self._show_privileged_hint()
            else:
                configs.append(self._build_advanced_config(os_targets, include_os=True))
        if not configs:
            return
        first = configs[0]
        self._pending_scan_configs = configs[1:]
        self._active_scan_kind = "advanced"
        self._current_scan_targets = list(first.targets)
        self._scan_active = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.statusBar().showMessage(self._t("advanced_running_status"))
        self._summary_status = self._t("advanced_running_status")
        self._update_summary()
        self._announce_advanced_eta(len(first.targets))
        self._ensure_log_dialog(first.targets, show=False, reset=True)
        self._scan_manager.start(first)
        self._refresh_action_buttons()

    def _on_run_safety_clicked(self) -> None:
        if self._scan_active:
            QMessageBox.information(
                self,
                self._t("safe_scan_blocked_title"),
                self._t("safe_scan_blocked_body"),
            )
            return
        if self._safe_scan_active or self._safe_scan_manager.is_running():
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
        self._safe_scan_manager.start(targets)
        self._refresh_action_buttons()

    def _on_show_log_clicked(self) -> None:
        if not self._log_dialog:
            return
        self._log_dialog.show()
        self._log_dialog.raise_()
        self._log_dialog.activateWindow()

    def _on_stop_clicked(self) -> None:
        self._scan_manager.stop()
        self._pending_scan_configs.clear()
        self._active_scan_kind = None
        self._current_scan_targets = []
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(self._t("scan_stopped"))
        self._summary_status = self._t("scan_stopped")
        self._scan_active = False
        self._job_eta.stop("advanced")
        self._update_summary()
        self._refresh_action_buttons()
        if self._log_dialog:
            self._log_dialog.mark_scan_finished()

    def _on_scan_started(self, total: int) -> None:
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(0)

    def _on_progress(self, done: int, total: int) -> None:
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(done)

    def _on_result(self, result: HostScanResult) -> None:
        if self._active_scan_kind == "advanced":
            self._handle_advanced_result(result)
        else:
            self._handle_fast_result(result)
        self._update_summary()
        self._on_form_state_changed()

    def _reset_result_storage(self, *, emit_selection_changed: bool = True) -> None:
        self._results.clear()
        self._result_lookup = {}
        self._result_grid.reset(emit_signal=emit_selection_changed)
        self._update_mac_limited_label()

    def _on_result_grid_selection_changed(self) -> None:
        self._refresh_action_buttons()
        self._on_form_state_changed()

    def _merge_result(self, existing: HostScanResult, new_result: HostScanResult) -> None:
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

    def _set_diagnostics_status(self, target: str, status: str) -> None:
        result = self._result_lookup.get(target)
        if not result:
            return
        result.diagnostics_status = status
        result.diagnostics_updated_at = datetime.now().astimezone().isoformat()
        self._result_grid.update_result(result, allow_sort_restore=False)

    def _refresh_action_buttons(self) -> None:
        advanced_allowed = (
            not self._scan_active and not self._safe_scan_active and self._result_grid.has_advanced_selection()
        )
        safety_allowed = (
            not self._scan_active and not self._safe_scan_active and self._result_grid.has_safety_selection()
        )
        self._result_grid.set_run_buttons_enabled(advanced=advanced_allowed, safety=safety_allowed)
        if self.clear_button:
            self.clear_button.setEnabled(not self._scan_active and not self._safe_scan_active)
        if not self._scan_active and not self._safe_scan_active:
            self.start_button.setEnabled(True)

    def _update_mac_limited_label(self) -> None:
        if not hasattr(self, "mac_limited_label"):
            return
        limited = self._is_macos_limited()
        if limited:
            self.mac_limited_label.setText(self._t("mac_limited_body"))
            self.mac_limited_label.setVisible(True)
        else:
            self.mac_limited_label.clear()
            self.mac_limited_label.setVisible(False)
        self._result_grid.set_os_selection_allowed(
            not limited,
            tooltip=self._t("mac_limited_body"),
        )

    def _is_macos_limited(self) -> bool:
        return sys.platform == "darwin" and not self._running_as_root()

    def _running_as_root(self) -> bool:
        geteuid = getattr(os, "geteuid", None)
        if callable(geteuid):
            return geteuid() == 0
        return True

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
        self._summary_status = self._t("placeholder_error_status")
        self._update_summary()
        return True

    def _handle_fast_result(self, result: HostScanResult) -> None:
        if self._consume_placeholder_error(result):
            return
        existing = self._result_lookup.get(result.target)
        if existing:
            self._merge_result(existing, result)
            self._result_grid.update_result(existing)
        else:
            self._results.append(result)
            self._result_lookup[result.target] = result
            self._result_grid.update_result(result)

    def _handle_advanced_result(self, result: HostScanResult) -> None:
        if self._consume_placeholder_error(result):
            return
        existing = self._result_lookup.get(result.target)
        if existing:
            self._merge_result(existing, result)
            self._result_grid.update_result(existing)
        else:
            self._results.append(result)
            self._result_lookup[result.target] = result
            self._result_grid.update_result(result)

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

    def _build_safe_eta_message(self, remaining: float) -> str:
        total = max(self._safe_scan_batch_total, 1)
        done = min(self._safe_scan_completed, total)
        eta_text = self._format_eta_seconds(remaining)
        return self._t("safe_scan_progress_running_multi").format(
            done=done,
            total=total,
            eta=eta_text,
        )
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



    def _record_safe_scan_duration(self, duration: float) -> None:
        if duration <= 0:
            return
        self._safe_scan_history.append(duration)
        if len(self._safe_scan_history) > self._settings.safe_scan.history_limit:
            self._safe_scan_history.pop(0)
        average = sum(self._safe_scan_history) / len(self._safe_scan_history)
        timeout = float(self._settings.safe_scan.timeout_seconds)
        baseline = float(self._settings.safe_scan.default_duration_seconds)
        self._safe_scan_expected_duration = min(timeout, max(baseline, average))

    def _on_safe_scan_started(self, total: int) -> None:
        self._safe_scan_active = True
        self._safe_scan_batch_total = total
        self._safe_scan_completed = 0
        self._safe_scan_elapsed_start = time.monotonic()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self._refresh_action_buttons()
        per_host = max(self._safe_scan_expected_duration, 1.0)
        expected = self._estimate_parallel_total_seconds(
            total,
            per_host,
            timeout_seconds=float(self._settings.safe_scan.timeout_seconds),
            parallelism=self._safe_scan_parallel,
        )
        self._job_eta.start(
            kind="safe",
            expected_seconds=expected,
            message_builder=self._build_safe_eta_message,
        )

    def _on_safe_scan_progress(self, done: int, total: int) -> None:
        self._safe_scan_completed = done
        self._safe_scan_batch_total = total
        self._job_eta.refresh("safe")

    def _on_safe_scan_result(self, report: SafeScanReport) -> None:
        self._set_diagnostics_status(report.target, "completed" if report.success else "failed")
        self._result_grid.clear_safety_selection_for_target(report.target)
        dialog = SafeScanDialog(self, report, self._language)
        dialog.exec()
        if dialog.saved_path:
            self.statusBar().showMessage(
                self._t("safe_scan_save_success_body").format(path=dialog.saved_path)
            )
        self._record_safe_scan_duration(report.duration_seconds)
        self._refresh_action_buttons()

    def _on_safe_scan_error(self, payload) -> None:
        message = str(payload)
        QMessageBox.critical(
            self,
            self._t("safe_scan_error_title"),
            self._t("safe_scan_error_body").format(message=message),
        )
        self.statusBar().showMessage(message)
        self._summary_status = message
        self._update_summary()
        self._job_eta.stop("safe")

    def _on_safe_scan_finished(self) -> None:
        duration: float | None = None
        if self._safe_scan_elapsed_start is not None:
            duration = time.monotonic() - self._safe_scan_elapsed_start
        completed_total = self._safe_scan_batch_total
        self._safe_scan_active = False
        self._safe_scan_targets = []
        if not self._scan_active:
            self.start_button.setEnabled(True)
        self.stop_button.setEnabled(self._scan_active)
        self._refresh_action_buttons()
        self._job_eta.stop("safe")
        self._safe_scan_elapsed_start = None
        if not self._scan_active:
            if duration is not None and duration > 0:
                finished_message = self._t("safe_scan_progress_complete_multi").format(
                    seconds=int(round(duration)),
                    total=max(completed_total, 1),
                )
            else:
                finished_message = self._t("safe_scan_progress_finished")
            self.statusBar().showMessage(finished_message)
            self._summary_status = finished_message
            self._update_summary()
        self._safe_scan_batch_total = 0
        self._safe_scan_completed = 0

    def _on_error(self, payload) -> None:
        if isinstance(payload, ErrorRecord):
            message = format_error_record(payload, self._language)
        else:
            message = str(payload)
        QMessageBox.critical(self, self._t("scan_error_title"), message)
        self.statusBar().showMessage(message)
        self._summary_has_error = True
        self._summary_status = message
        self._update_summary()
        self._job_eta.stop("advanced")
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
            self._update_summary()
            self._scan_manager.start(next_config)
            return
        self._job_eta.stop("advanced")
        self._scan_active = False
        self._pending_scan_configs.clear()
        self._active_scan_kind = None
        self._current_scan_targets = []
        self.start_button.setEnabled(not self._safe_scan_active)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(self._t("scan_finished"))
        if not self._summary_has_error:
            if self._results:
                self._summary_status = self._t("scan_finished")
            else:
                self._summary_status = self._t("summary_status_no_hosts")
        self._update_summary()
        self._refresh_action_buttons()
        if self._log_dialog:
            self._log_dialog.mark_scan_finished()

    def _t(self, key: str) -> str:
        return translate(key, self._language)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._scan_manager.stop()
        self._safe_scan_manager.stop()
        if self._log_dialog:
            self._log_dialog.deleteLater()
            self._log_dialog = None
        if self.log_button:
            self.log_button.setEnabled(False)
        self._state_save_timer.stop()
        if not self._persist_state(on_close=True):
            event.ignore()
            return
        super().closeEvent(event)

    def _export_csv(self) -> None:
        if not self._results:
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
        export_csv(path, self._results, language=self._language)
        self.statusBar().showMessage(self._t("export_csv_done").format(path=path))

    def _export_json(self) -> None:
        if not self._results:
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
        export_json(path, self._results, language=self._language)
        self.statusBar().showMessage(self._t("export_json_done").format(path=path))

    def _initialize_state(self, provided: AppState | None) -> AppState:
        if provided:
            return provided
        state = load_state()
        if state:
            return state
        state = AppState()
        if not save_state(state):
            self._disable_state_persistence = True
        return state

    def _apply_state_to_widgets(self) -> None:
        state = self._app_state
        self.target_input.setPlainText(state.targets_text)
        if state.window_geometry:
            try:
                self.restoreGeometry(QByteArray(state.window_geometry))
            except TypeError:
                pass
        self._reset_result_storage()
        self._result_grid.set_selections(
            advanced=state.advanced_selected,
            os_targets=state.os_selected,
            safety=state.safety_selected,
            emit_signal=False,
        )
        self._restore_results_from_state(state.results)

    def _restore_results_from_state(self, stored: List[HostScanResult]) -> None:
        if stored:
            for item in stored:
                result = copy.deepcopy(item)
                self._results.append(result)
                self._result_lookup[result.target] = result
                self._result_grid.update_result(result, allow_sort_restore=False)
        self._update_summary()

    def _connect_state_change_signals(self) -> None:
        self.target_input.textChanged.connect(self._on_form_state_changed)

    def _on_form_state_changed(self, *_args) -> None:
        if self._disable_state_persistence:
            return
        self._state_save_timer.start()

    def _collect_state_from_widgets(self) -> AppState:
        return AppState(
            targets_text=self.target_input.toPlainText(),
            icmp_enabled=True,
            ports_enabled=True,
            os_enabled=False,
            window_geometry=bytes(self.saveGeometry()),
            results=copy.deepcopy(self._results),
            advanced_selected=self._result_grid.advanced_targets(),
            os_selected=self._result_grid.os_targets(),
            safety_selected=self._result_grid.safety_targets(),
        )

    def _persist_state(self, state: AppState | None = None, *, on_close: bool = False) -> bool:
        if self._disable_state_persistence:
            return True
        snapshot = state or self._collect_state_from_widgets()
        saved = save_state(snapshot)
        if saved:
            self._app_state = snapshot
            return True
        self._disable_state_persistence = True
        self._state_save_timer.stop()
        keep_running = self._prompt_storage_warnings()
        if on_close:
            return not keep_running
        if not keep_running:
            QTimer.singleShot(0, self.close)
        return True

    def _prompt_storage_warnings(self) -> bool:
        warnings = consume_storage_warnings()
        if not warnings:
            return True
        if any(w.scope == "state" for w in warnings):
            self._disable_state_persistence = True
        detail_text = "\n\n".join(self._format_storage_warning(w) for w in warnings)
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Warning)
        dialog.setWindowTitle(self._t("storage_warning_title"))
        dialog.setText(self._t("storage_warning_body"))
        dialog.setInformativeText(detail_text)
        continue_button = dialog.addButton(self._t("storage_warning_continue"), QMessageBox.ButtonRole.AcceptRole)
        dialog.addButton(self._t("storage_warning_exit"), QMessageBox.ButtonRole.RejectRole)
        dialog.setDefaultButton(continue_button)
        dialog.exec()
        return dialog.clickedButton() is continue_button

    def _format_storage_warning(self, warning: StorageWarning) -> str:
        scope_label = self._storage_scope_label(warning.scope)
        action_label = self._storage_action_label(warning.action)
        return self._t("storage_warning_line").format(
            scope=scope_label,
            action=action_label,
            path=str(warning.path),
            detail=warning.detail,
        )

    def _storage_scope_label(self, scope: str) -> str:
        key = f"storage_scope_{scope}"
        label = translate(key, self._language)
        return label if label != key else scope

    def _storage_action_label(self, action: str) -> str:
        key = f"storage_action_{action}"
        label = translate(key, self._language)
        return label if label != key else action

    def _has_required_privileges(self, modes: Set[ScanMode]) -> bool:
        """Return True when OS scans are either disabled or elevated privileges exist."""
        if ScanMode.OS not in modes:
            return True
        if os.name == "nt":
            return True
        geteuid = getattr(os, "geteuid", None)
        if not callable(geteuid):
            return True
        return geteuid() == 0

    def _show_privileged_hint(self) -> None:
        """Inform the user that sudo is required to run OS fingerprinting."""
        command = self._privileged_launch_command()
        QMessageBox.information(
            self,
            self._t("privileged_os_required_title"),
            self._t("privileged_os_required_body").format(command=command),
        )

    def _privileged_launch_command(self) -> str:
        """Suggest a sudo command that re-launches the current binary."""
        if getattr(sys, "frozen", False):
            executable = Path(sys.executable).resolve()
            return f"sudo {shlex.quote(str(executable))}"
        python = sys.executable or "python3"
        python_path = shlex.quote(str(Path(python).resolve()))
        return f"sudo {python_path} -m nmap_gui.main --debug"

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
        if self.log_button:
            self.log_button.setEnabled(True)

    def _on_log_dialog_destroyed(self, _obj=None) -> None:
        self._log_dialog = None
        if self.log_button:
            self.log_button.setEnabled(False)

    def _on_log_event(self, event: ScanLogEvent) -> None:
        if not isinstance(event, ScanLogEvent):
            return
        if self._log_dialog:
            self._log_dialog.append_event(event)
