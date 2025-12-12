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

from PySide6.QtCore import QByteArray, Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
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
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .config import AppSettings, get_settings
from .exporters import export_csv, export_json
from .i18n import detect_language, format_error_list, format_error_record, translate
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


TARGET_COLUMN_INDEX = 0
ALIVE_COLUMN_INDEX = 1
PORTS_COLUMN_INDEX = 2
OS_COLUMN_INDEX = 3
SCORE_COLUMN_INDEX = 4
PRIORITY_COLUMN_INDEX = 5
ERROR_COLUMN_INDEX = 6
ADVANCED_COLUMN_INDEX = 7
OS_OPTION_COLUMN_INDEX = 8
SAFETY_COLUMN_INDEX = 9
DIAGNOSTICS_COLUMN_INDEX = 10
DEFAULT_PRIORITY_COLORS = {
    "High": QColor(255, 204, 204),
    "Medium": QColor(255, 240, 210),
    "Low": QColor(210, 235, 255),
}


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

    def _format_eta_seconds(self, seconds: float) -> str:
        total = max(int(round(seconds)), 0)
        mins, secs = divmod(total, 60)
        hours, mins = divmod(mins, 60)
        if hours:
            return f"{hours:d}:{mins:02d}:{secs:02d}"
        return f"{mins:02d}:{secs:02d}"

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
        self._result_index: Dict[str, int] = {}
        self._result_lookup: Dict[str, HostScanResult] = {}
        self._row_checkboxes: Dict[str, Dict[str, QCheckBox]] = {}
        self._advanced_selection: Set[str] = set()
        self._os_selection: Set[str] = set()
        self._safety_selection: Set[str] = set()
        self._pending_scan_configs: List[ScanConfig] = []
        self._active_scan_kind: str | None = None
        self._current_scan_targets: List[str] = []
        self.advanced_select_all_checkbox: QCheckBox | None = None
        self.os_select_all_checkbox: QCheckBox | None = None
        self.safety_select_all_checkbox: QCheckBox | None = None
        self.run_advanced_button: QPushButton | None = None
        self.run_safety_button: QPushButton | None = None
        self.log_button: QPushButton | None = None
        self._scan_manager = ScanManager(self._settings)
        self._safe_scan_manager = SafeScriptManager(self._settings)
        self._sort_column: int | None = None
        self._sort_order = Qt.AscendingOrder
        self.summary_label: QLabel | None = None
        self._target_count = 0
        self._requested_host_estimate = 0
        self._summary_status = self._t("summary_status_idle")
        self._summary_has_error = False
        self._safe_scan_active = False
        self._scan_active = False
        self._safe_scan_expected_duration = float(self._settings.safe_scan.timeout_seconds)
        self._safe_scan_history: List[float] = []
        self._safe_scan_elapsed_start: float | None = None
        self._safe_scan_targets: List[str] = []
        self._safe_scan_batch_total = 0
        self._safe_scan_batch_expected_duration = 0.0
        self._safe_scan_completed = 0
        self._safe_scan_parallel = max(1, self._settings.safe_scan.max_parallel)
        self._safe_progress_timer = QTimer(self)
        self._safe_progress_timer.timeout.connect(self._on_safe_progress_tick)
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
        layout.addWidget(self._create_table())
        layout.addLayout(self._create_table_action_bar())
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

    def _create_table(self) -> QWidget:
        self.table = QTableWidget(0, 11)
        self.table.setHorizontalHeaderLabels(
            [
                self._t("table_target"),
                self._t("table_alive"),
                self._t("table_ports"),
                self._t("table_os"),
                self._t("table_score"),
                self._t("table_priority"),
                self._t("table_errors"),
                self._t("table_advanced"),
                self._t("table_os_option"),
                self._t("table_safety"),
                self._t("table_diagnostics_status"),
            ]
        )
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSortIndicatorShown(False)
        header.setSectionsClickable(True)
        header.sectionClicked.connect(self._handle_sort_request)
        self.table.setSortingEnabled(False)
        self.table.setWordWrap(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        return self.table

    def _create_table_action_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.addWidget(QLabel(self._t("advanced_select_label")))
        self.advanced_select_all_checkbox = QCheckBox(self._t("select_all"))
        self.advanced_select_all_checkbox.stateChanged.connect(
            lambda state: self._toggle_all_checkboxes("advanced", state)
        )
        bar.addWidget(self.advanced_select_all_checkbox)
        self.os_select_all_checkbox = QCheckBox(self._t("select_all_os"))
        self.os_select_all_checkbox.stateChanged.connect(
            lambda state: self._toggle_all_checkboxes("os", state)
        )
        bar.addWidget(self.os_select_all_checkbox)
        self.run_advanced_button = QPushButton(self._t("run_advanced_button"))
        self.run_advanced_button.clicked.connect(self._on_run_advanced_clicked)
        bar.addWidget(self.run_advanced_button)
        bar.addSpacing(20)
        bar.addWidget(QLabel(self._t("safety_select_label")))
        self.safety_select_all_checkbox = QCheckBox(self._t("select_all"))
        self.safety_select_all_checkbox.stateChanged.connect(
            lambda state: self._toggle_all_checkboxes("safety", state)
        )
        bar.addWidget(self.safety_select_all_checkbox)
        self.run_safety_button = QPushButton(self._t("run_safety_button"))
        self.run_safety_button.clicked.connect(self._on_run_safety_clicked)
        bar.addWidget(self.run_safety_button)
        bar.addStretch()
        return bar

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
        self.safe_progress_label = QLabel(self._t("safe_scan_progress_idle"))
        self.safe_progress_bar = QProgressBar()
        self.safe_progress_bar.setRange(0, 100)
        self.safe_progress_bar.setValue(0)
        self.safe_progress_label.setVisible(False)
        self.safe_progress_bar.setVisible(False)
        layout.addWidget(self.safe_progress_label)
        layout.addWidget(self.safe_progress_bar)
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
        self._reset_result_storage()
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
        self._results.clear()
        self._result_lookup.clear()
        self._result_index.clear()
        self._row_checkboxes.clear()
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
        if not self._advanced_selection:
            QMessageBox.information(
                self,
                self._t("advanced_missing_title"),
                self._t("advanced_missing_body"),
            )
            return
        os_targets = sorted(target for target in self._advanced_selection if target in self._os_selection)
        base_targets = sorted(target for target in self._advanced_selection if target not in self._os_selection)
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
        if not self._safety_selection:
            QMessageBox.information(
                self,
                self._t("safe_scan_missing_title"),
                self._t("safe_scan_missing_body"),
            )
            return
        targets = sorted(self._safety_selection)
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

    def _make_item(
        self, text: str, alignment: Qt.AlignmentFlag | None = None
    ) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        if alignment is not None:
            item.setTextAlignment(int(alignment | Qt.AlignVCenter))
        return item

    def _reset_result_storage(self) -> None:
        self._results.clear()
        self._result_lookup: Dict[str, HostScanResult] = {}
        self._result_index.clear()
        self._row_checkboxes.clear()
        self._advanced_selection.clear()
        self._os_selection.clear()
        self._safety_selection.clear()
        self.table.setRowCount(0)
        self._sync_select_all_checkboxes()
        self._update_mac_limited_label()
        self._update_select_all_enabled()

    def _insert_row_for_result(
        self,
        result: HostScanResult,
        *,
        allow_sort_restore: bool = True,
    ) -> None:
        sorting_enabled = self.table.isSortingEnabled()
        if sorting_enabled:
            self.table.setSortingEnabled(False)
        row = self.table.rowCount()
        self.table.insertRow(row)
        self._populate_row(row, result)
        self._attach_row_checkboxes(row, result.target)
        self._result_index[result.target] = row
        self._update_select_all_enabled()
        if sorting_enabled:
            self.table.setSortingEnabled(True)
            if allow_sort_restore and self._sort_column is not None:
                self.table.sortItems(self._sort_column, self._sort_order)
                self._rebuild_row_index_from_table()

    def _populate_row(self, row: int, result: HostScanResult) -> None:
        self.table.setItem(row, TARGET_COLUMN_INDEX, self._make_item(result.target, Qt.AlignLeft))
        alive_text = self._t("alive_yes") if result.is_alive else self._t("alive_no")
        self.table.setItem(row, ALIVE_COLUMN_INDEX, self._make_item(alive_text, Qt.AlignCenter))
        ports_text = ", ".join(str(p) for p in result.open_ports)
        self.table.setItem(row, PORTS_COLUMN_INDEX, self._make_item(ports_text, Qt.AlignLeft))
        os_text = result.os_guess
        if result.os_accuracy is not None:
            os_text = f"{os_text} ({result.os_accuracy}%)"
        self.table.setItem(row, OS_COLUMN_INDEX, self._make_item(os_text, Qt.AlignLeft))
        self.table.setItem(row, SCORE_COLUMN_INDEX, self._make_item(str(result.score), Qt.AlignRight))
        display_priority = self._priority_labels.get(result.priority, result.priority)
        priority_item = self._make_item(display_priority, Qt.AlignCenter)
        self.table.setItem(row, PRIORITY_COLUMN_INDEX, priority_item)
        error_text = "\n".join(format_error_list(result.errors, self._language))
        self.table.setItem(row, ERROR_COLUMN_INDEX, self._make_item(error_text, Qt.AlignLeft))
        diag_label = self._diagnostics_status_label(result.diagnostics_status)
        self.table.setItem(row, DIAGNOSTICS_COLUMN_INDEX, self._make_item(diag_label, Qt.AlignCenter))
        self._apply_row_style(row, result.priority)

    def _attach_row_checkboxes(self, row: int, target: str) -> None:
        advanced_cb = QCheckBox()
        advanced_cb.setChecked(target in self._advanced_selection)
        advanced_cb.stateChanged.connect(
            lambda state, t=target: self._on_row_checkbox_changed("advanced", t, state)
        )
        self.table.setCellWidget(row, ADVANCED_COLUMN_INDEX, self._wrap_checkbox_widget(advanced_cb))

        os_cb = QCheckBox()
        os_cb.setChecked(target in self._os_selection)
        os_allowed = self._is_os_selection_allowed()
        os_cb.setEnabled(os_allowed and target in self._advanced_selection)
        if not os_allowed:
            os_cb.setToolTip(self._t("mac_limited_body"))
        os_cb.stateChanged.connect(
            lambda state, t=target: self._on_row_checkbox_changed("os", t, state)
        )
        self.table.setCellWidget(row, OS_OPTION_COLUMN_INDEX, self._wrap_checkbox_widget(os_cb))

        safety_cb = QCheckBox()
        safety_cb.setChecked(target in self._safety_selection)
        safety_cb.stateChanged.connect(
            lambda state, t=target: self._on_row_checkbox_changed("safety", t, state)
        )
        self.table.setCellWidget(row, SAFETY_COLUMN_INDEX, self._wrap_checkbox_widget(safety_cb))

        self._row_checkboxes[target] = {
            "advanced": advanced_cb,
            "os": os_cb,
            "safety": safety_cb,
        }

    def _wrap_checkbox_widget(self, checkbox: QCheckBox) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(checkbox, alignment=Qt.AlignCenter)
        return widget

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

    def _update_row_for_target(self, target: str) -> None:
        row = self._result_index.get(target)
        result = self._result_lookup.get(target)
        if row is None or result is None:
            return
        self._populate_row(row, result)

    def _diagnostics_status_label(self, status: str) -> str:
        key_map = {
            "not_started": "diagnostics_status_not_started",
            "running": "diagnostics_status_running",
            "completed": "diagnostics_status_completed",
            "failed": "diagnostics_status_failed",
        }
        return self._t(key_map.get(status, "diagnostics_status_not_started"))

    def _set_diagnostics_status(self, target: str, status: str) -> None:
        result = self._result_lookup.get(target)
        if not result:
            return
        result.diagnostics_status = status
        result.diagnostics_updated_at = datetime.now().astimezone().isoformat()
        self._update_row_for_target(target)

    def _on_row_checkbox_changed(self, kind: str, target: str, state: int) -> None:
        checked = Qt.CheckState(state) == Qt.CheckState.Checked
        if kind == "advanced":
            if checked:
                self._advanced_selection.add(target)
                checkbox = self._row_checkboxes.get(target, {}).get("os")
                if checkbox:
                    checkbox.setEnabled(self._is_os_selection_allowed())
            else:
                self._advanced_selection.discard(target)
                self._os_selection.discard(target)
                checkbox = self._row_checkboxes.get(target, {}).get("os")
                if checkbox:
                    checkbox.blockSignals(True)
                    checkbox.setChecked(False)
                    checkbox.setEnabled(False)
                    checkbox.blockSignals(False)
            self._refresh_os_checkbox_states()
        elif kind == "os":
            if target not in self._advanced_selection:
                checkbox = self._row_checkboxes.get(target, {}).get("os")
                if checkbox:
                    checkbox.blockSignals(True)
                    checkbox.setChecked(False)
                    checkbox.blockSignals(False)
                return
            if checked:
                self._os_selection.add(target)
            else:
                self._os_selection.discard(target)
        elif kind == "safety":
            if checked:
                self._safety_selection.add(target)
            else:
                self._safety_selection.discard(target)
        self._sync_select_all_checkboxes()
        self._refresh_action_buttons()
        self._on_form_state_changed()

    def _toggle_all_checkboxes(self, kind: str, state: int) -> None:
        checked = Qt.CheckState(state) == Qt.CheckState.Checked
        if not self._row_checkboxes:
            return
        targets = list(self._row_checkboxes.keys())
        if kind == "os" and checked:
            targets = [target for target in targets if target in self._advanced_selection]
        for target in targets:
            checkbox = self._row_checkboxes.get(target, {}).get(kind)
            if checkbox is None:
                continue
            checkbox.blockSignals(True)
            checkbox.setChecked(checked)
            checkbox.blockSignals(False)
            self._on_row_checkbox_changed(kind, target, Qt.Checked if checked else Qt.Unchecked)
        self._sync_select_all_checkboxes()

    def _sync_select_all_checkboxes(self) -> None:
        total_rows = len(self._row_checkboxes)
        self._set_select_all_state(self.advanced_select_all_checkbox, len(self._advanced_selection), total_rows)
        advanced_count = len(self._advanced_selection)
        self._set_select_all_state(
            self.os_select_all_checkbox,
            len(self._os_selection),
            advanced_count or total_rows,
        )
        self._set_select_all_state(self.safety_select_all_checkbox, len(self._safety_selection), total_rows)

    def _set_select_all_state(self, checkbox: QCheckBox, selected: int, total: int) -> None:
        if checkbox is None:
            return
        checkbox.blockSignals(True)
        checkbox.setCheckState(Qt.Checked if total > 0 and selected == total else Qt.Unchecked)
        checkbox.blockSignals(False)

    def _rebuild_row_index_from_table(self) -> None:
        self._result_index.clear()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, TARGET_COLUMN_INDEX)
            if item:
                self._result_index[item.text()] = row

    def _clear_completed_advanced_selection(self, targets: Sequence[str]) -> None:
        for target in targets:
            self._advanced_selection.discard(target)
            self._os_selection.discard(target)
            widgets = self._row_checkboxes.get(target, {})
            adv_cb = widgets.get("advanced")
            if adv_cb:
                adv_cb.blockSignals(True)
                adv_cb.setChecked(False)
                adv_cb.blockSignals(False)
            os_cb = widgets.get("os")
            if os_cb:
                os_cb.blockSignals(True)
                os_cb.setChecked(False)
                os_cb.setEnabled(False)
                os_cb.blockSignals(False)
        self._sync_select_all_checkboxes()
        self._refresh_action_buttons()
        self._on_form_state_changed()

    def _clear_safety_selection_for_target(self, target: str) -> None:
        self._safety_selection.discard(target)
        checkbox = self._row_checkboxes.get(target, {}).get("safety")
        if checkbox:
            checkbox.blockSignals(True)
            checkbox.setChecked(False)
            checkbox.blockSignals(False)
        self._sync_select_all_checkboxes()
        self._refresh_action_buttons()
        self._on_form_state_changed()

    def _refresh_action_buttons(self) -> None:
        advanced_allowed = (
            not self._scan_active and not self._safe_scan_active and bool(self._advanced_selection)
        )
        safety_allowed = (
            not self._scan_active and not self._safe_scan_active and bool(self._safety_selection)
        )
        if self.run_advanced_button:
            self.run_advanced_button.setEnabled(advanced_allowed)
        if self.run_safety_button:
            self.run_safety_button.setEnabled(safety_allowed)
        if self.clear_button:
            self.clear_button.setEnabled(not self._scan_active and not self._safe_scan_active)
        if not self._scan_active and not self._safe_scan_active:
            self.start_button.setEnabled(True)

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

    def _update_mac_limited_label(self) -> None:
        if not hasattr(self, "mac_limited_label"):
            return
        if self._is_macos_limited():
            self.mac_limited_label.setText(self._t("mac_limited_body"))
            self.mac_limited_label.setVisible(True)
        else:
            self.mac_limited_label.clear()
            self.mac_limited_label.setVisible(False)
        self._update_os_select_all_enabled()
        self._refresh_os_checkbox_states()
        self._sync_select_all_checkboxes()

    def _is_macos_limited(self) -> bool:
        return sys.platform == "darwin" and not self._running_as_root()

    def _running_as_root(self) -> bool:
        geteuid = getattr(os, "geteuid", None)
        if callable(geteuid):
            return geteuid() == 0
        return True

    def _is_os_selection_allowed(self) -> bool:
        return not self._is_macos_limited()

    def _update_select_all_enabled(self) -> None:
        has_rows = bool(self._row_checkboxes)
        if self.advanced_select_all_checkbox:
            self.advanced_select_all_checkbox.setEnabled(has_rows)
        if self.safety_select_all_checkbox:
            self.safety_select_all_checkbox.setEnabled(has_rows)
        self._update_os_select_all_enabled()

    def _update_os_select_all_enabled(self) -> None:
        if not self.os_select_all_checkbox:
            return
        allowed = self._is_os_selection_allowed()
        has_rows = bool(self._row_checkboxes)
        self.os_select_all_checkbox.setEnabled(allowed and has_rows)
        if not allowed:
            self.os_select_all_checkbox.setCheckState(Qt.Unchecked)

    def _refresh_os_checkbox_states(self) -> None:
        allowed = self._is_os_selection_allowed()
        for target, widgets in self._row_checkboxes.items():
            os_cb = widgets.get("os")
            if not os_cb:
                continue
            enable = allowed and (target in self._advanced_selection)
            os_cb.setEnabled(enable)
            if not enable and os_cb.isChecked():
                os_cb.blockSignals(True)
                os_cb.setChecked(False)
                os_cb.blockSignals(False)
                self._os_selection.discard(target)

    def _handle_fast_result(self, result: HostScanResult) -> None:
        if self._consume_placeholder_error(result):
            return
        existing = self._result_lookup.get(result.target)
        if existing:
            self._merge_result(existing, result)
            self._update_row_for_target(result.target)
        else:
            self._results.append(result)
            self._result_lookup[result.target] = result
            self._insert_row_for_result(result)

    def _handle_advanced_result(self, result: HostScanResult) -> None:
        if self._consume_placeholder_error(result):
            return
        existing = self._result_lookup.get(result.target)
        if existing:
            self._merge_result(existing, result)
            self._update_row_for_target(result.target)
        else:
            self._results.append(result)
            self._result_lookup[result.target] = result
            self._insert_row_for_result(result)

    def _announce_advanced_eta(self, target_count: int) -> None:
        eta_seconds = self._estimate_parallel_total_seconds(
            target_count,
            float(self._settings.scan.advanced_timeout_seconds),
            timeout_seconds=float(self._settings.scan.advanced_timeout_seconds),
            parallelism=self._settings.scan.advanced_max_parallel,
        )
        eta_text = self._format_eta_seconds(eta_seconds)
        message = self._t("advanced_running_status_eta").format(eta=eta_text)
        self.statusBar().showMessage(message)
        self._summary_status = message
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

    def _apply_row_style(self, row: int, priority: str) -> None:
        color = self._priority_color(priority)
        if not color:
            return
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(color)

    def _priority_color(self, priority: str) -> QColor | None:
        color_hex = self._settings.ui.priority_colors.get(priority)
        if color_hex:
            return QColor(color_hex)
        return DEFAULT_PRIORITY_COLORS.get(priority)

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


    def _ensure_safe_progress_visible(self) -> None:
        self.safe_progress_label.setVisible(True)
        self.safe_progress_bar.setVisible(True)

    def _hide_safe_progress(self) -> None:
        if self._safe_scan_active:
            return
        self.safe_progress_label.setVisible(False)
        self.safe_progress_bar.setVisible(False)

    def _start_safe_progress(self) -> None:
        self._safe_scan_elapsed_start = time.monotonic()
        total = max(self._safe_scan_batch_total, 1)
        self._safe_scan_batch_expected_duration = self._estimate_parallel_total_seconds(
            total,
            self._safe_scan_expected_duration,
            timeout_seconds=float(self._settings.safe_scan.timeout_seconds),
            parallelism=self._safe_scan_parallel,
        )
        self._safe_scan_completed = 0
        self.safe_progress_bar.setValue(0)
        self.safe_progress_bar.setFormat("%p%")
        remaining, _ = self._safe_scan_progress_snapshot(0.0)
        self._update_safe_progress_label(0.0, remaining)
        self._ensure_safe_progress_visible()
        if not self._safe_progress_timer.isActive():
            self._safe_progress_timer.start(self._settings.safe_scan.progress_update_ms)

    def _safe_scan_progress_snapshot(self, elapsed_seconds: float) -> tuple[float, float]:
        remaining_jobs = max(self._safe_scan_batch_total - self._safe_scan_completed, 0)
        remaining_seconds = self._estimate_parallel_total_seconds(
            remaining_jobs,
            self._safe_scan_expected_duration,
            timeout_seconds=float(self._settings.safe_scan.timeout_seconds),
            parallelism=self._safe_scan_parallel,
        )
        total_seconds = elapsed_seconds + remaining_seconds
        if remaining_jobs == 0 and self._safe_scan_completed >= self._safe_scan_batch_total:
            remaining_seconds = 0.0
            total_seconds = elapsed_seconds
        self._safe_scan_batch_expected_duration = max(total_seconds, 1.0)
        return remaining_seconds, self._safe_scan_batch_expected_duration

    def _on_safe_progress_tick(self) -> None:
        if not self._safe_scan_active or self._safe_scan_elapsed_start is None:
            return
        elapsed = time.monotonic() - self._safe_scan_elapsed_start
        remaining, expected = self._safe_scan_progress_snapshot(elapsed)
        progress = 0
        if expected > 0:
            progress = min(int((elapsed / expected) * 100), 99)
        if self._safe_scan_batch_total:
            ratio = self._safe_scan_completed / self._safe_scan_batch_total
            progress = max(progress, int(ratio * 100))
        if remaining <= 0 and self._safe_scan_completed >= self._safe_scan_batch_total:
            progress = 100
        self.safe_progress_bar.setValue(progress)
        self._update_safe_progress_label(elapsed, remaining)

    def _update_safe_progress_label(self, elapsed_seconds: float, remaining_seconds: float) -> None:
        eta = self._format_eta_seconds(remaining_seconds)
        self.safe_progress_label.setText(
            self._t("safe_scan_progress_running_multi").format(
                done=self._safe_scan_completed,
                total=max(self._safe_scan_batch_total, 1),
                eta=eta,
            )
        )

    def _complete_safe_progress(self, duration: float | None) -> None:
        self._safe_progress_timer.stop()
        self.safe_progress_bar.setValue(100)
        if duration is not None:
            self.safe_progress_label.setText(
                self._t("safe_scan_progress_complete_multi").format(
                    seconds=int(round(duration)),
                    total=max(self._safe_scan_batch_total, 1),
                )
            )
        else:
            self.safe_progress_label.setText(self._t("safe_scan_progress_finished"))
        QTimer.singleShot(self._settings.safe_scan.progress_visibility_ms, self._hide_safe_progress)
        self._safe_scan_elapsed_start = None

    def _record_safe_scan_duration(self, duration: float) -> None:
        if duration <= 0:
            return
        self._safe_scan_history.append(duration)
        if len(self._safe_scan_history) > self._settings.safe_scan.history_limit:
            self._safe_scan_history.pop(0)
        average = sum(self._safe_scan_history) / len(self._safe_scan_history)
        timeout = float(self._settings.safe_scan.timeout_seconds)
        self._safe_scan_expected_duration = min(timeout, average)
        if self._safe_scan_active and self._safe_scan_elapsed_start is not None:
            elapsed = time.monotonic() - self._safe_scan_elapsed_start
            remaining, _ = self._safe_scan_progress_snapshot(elapsed)
            self._update_safe_progress_label(elapsed, remaining)

    def _handle_sort_request(self, column: int) -> None:
        if self._sort_column == column:
            self._sort_order = (
                Qt.DescendingOrder
                if self._sort_order == Qt.AscendingOrder
                else Qt.AscendingOrder
            )
        else:
            self._sort_column = column
            self._sort_order = Qt.AscendingOrder

        header = self.table.horizontalHeader()
        header.setSortIndicatorShown(True)
        header.setSortIndicator(column, self._sort_order)
        if not self.table.isSortingEnabled():
            self.table.setSortingEnabled(True)
        self.table.sortItems(column, self._sort_order)
        self._rebuild_row_index_from_table()

    def _on_safe_scan_started(self, total: int) -> None:
        self._safe_scan_active = True
        self._safe_scan_batch_total = total
        self._safe_scan_completed = 0
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(
            self._t("safe_scan_status_running_multi").format(total=total)
        )
        self._refresh_action_buttons()
        self._start_safe_progress()

    def _on_safe_scan_progress(self, done: int, total: int) -> None:
        self._safe_scan_completed = done
        self._safe_scan_batch_total = total
        if self._safe_scan_elapsed_start is not None:
            elapsed = time.monotonic() - self._safe_scan_elapsed_start
            remaining, _ = self._safe_scan_progress_snapshot(elapsed)
            self._update_safe_progress_label(elapsed, remaining)

    def _on_safe_scan_result(self, report: SafeScanReport) -> None:
        self._set_diagnostics_status(report.target, "completed" if report.success else "failed")
        self._clear_safety_selection_for_target(report.target)
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

    def _on_safe_scan_finished(self) -> None:
        duration: float | None = None
        if self._safe_scan_elapsed_start is not None:
            duration = time.monotonic() - self._safe_scan_elapsed_start
        self._safe_scan_active = False
        self._safe_scan_targets = []
        self._safe_scan_batch_total = 0
        self._safe_scan_completed = 0
        if not self._scan_active:
            self.start_button.setEnabled(True)
        self.stop_button.setEnabled(self._scan_active)
        if not self._scan_active:
            finished_message = self._t("safe_scan_status_finished_multi")
            self.statusBar().showMessage(finished_message)
        self._refresh_action_buttons()
        self._complete_safe_progress(duration)
        self._safe_scan_elapsed_start = None

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
        if self._log_dialog:
            self._log_dialog.mark_scan_finished()

    def _on_finished(self) -> None:
        completed_targets = list(self._current_scan_targets)
        if self._active_scan_kind == "advanced" and completed_targets:
            self._clear_completed_advanced_selection(completed_targets)
        if self._active_scan_kind == "advanced" and self._pending_scan_configs:
            next_config = self._pending_scan_configs.pop(0)
            self._current_scan_targets = list(next_config.targets)
            self._announce_advanced_eta(len(next_config.targets))
            self._ensure_log_dialog(next_config.targets, show=False, reset=True)
            self._update_summary()
            self._scan_manager.start(next_config)
            return
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
        self._advanced_selection = set(state.advanced_selected)
        self._os_selection = set(state.os_selected)
        self._safety_selection = set(state.safety_selected)
        self._restore_results_from_state(state.results)

    def _restore_results_from_state(self, stored: List[HostScanResult]) -> None:
        if not stored:
            self._reset_result_storage()
            self._update_summary()
            return
        self._reset_result_storage()
        for item in stored:
            result = copy.deepcopy(item)
            self._results.append(result)
            self._result_lookup[result.target] = result
            self._insert_row_for_result(result, allow_sort_restore=False)
        self._sync_select_all_checkboxes()
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
            advanced_selected=set(self._advanced_selection),
            os_selected=set(self._os_selection),
            safety_selected=set(self._safety_selection),
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
