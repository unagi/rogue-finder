"""PySide6 GUI for the Nmap discovery & rating application."""
from __future__ import annotations

import ipaddress
import os
import shlex
import sys
import time
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import List, Sequence, Set

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QPlainTextEdit,
    QProgressBar,
)

from .exporters import export_csv, export_json
from .i18n import detect_language, format_error_list, format_error_record, translate
from .models import (
    ErrorRecord,
    HostScanResult,
    SafeScanReport,
    ScanConfig,
    ScanMode,
    sanitize_targets,
)
from .scan_manager import SafeScriptManager, ScanManager
from .utils import slugify_filename_component


PRIORITY_COLORS = {
    "High": QColor(255, 204, 204),
    "Medium": QColor(255, 240, 210),
    "Low": QColor(210, 235, 255),
}

SAFE_SCAN_COLUMN_INDEX = 7
SAFE_SCAN_DEFAULT_DURATION = 120.0  # seconds
SAFE_SCAN_HISTORY_LIMIT = 20
SAFE_PROGRESS_UPDATE_MS = 500
SAFE_PROGRESS_VISIBILITY_MS = 4000


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


class MainWindow(QMainWindow):
    """Primary top-level window."""

    def __init__(self) -> None:
        super().__init__()
        self._language = detect_language()
        self._priority_labels = {
            "High": translate("priority_high", self._language),
            "Medium": translate("priority_medium", self._language),
            "Low": translate("priority_low", self._language),
        }
        self.setWindowTitle(self._t("window_title"))
        self.resize(1000, 700)
        self._results: List[HostScanResult] = []
        self._scan_manager = ScanManager()
        self._safe_scan_manager = SafeScriptManager()
        self._sort_column: int | None = None
        self._sort_order = Qt.AscendingOrder
        self.summary_label: QLabel | None = None
        self._target_count = 0
        self._requested_host_estimate = 0
        self._summary_status = self._t("summary_status_idle")
        self._summary_has_error = False
        self._safe_scan_active = False
        self._scan_active = False
        self._safe_scan_target: str | None = None
        self._safe_scan_expected_duration = SAFE_SCAN_DEFAULT_DURATION
        self._safe_scan_history: List[float] = []
        self._safe_scan_elapsed_start: float | None = None
        self._safe_progress_timer = QTimer(self)
        self._safe_progress_timer.timeout.connect(self._on_safe_progress_tick)
        self._setup_scan_manager()
        self._setup_safe_scan_manager()
        self._build_ui()

    def _setup_scan_manager(self) -> None:
        self._scan_manager.started.connect(self._on_scan_started)
        self._scan_manager.progress.connect(self._on_progress)
        self._scan_manager.result_ready.connect(self._on_result)
        self._scan_manager.error.connect(self._on_error)
        self._scan_manager.finished.connect(self._on_finished)

    def _setup_safe_scan_manager(self) -> None:
        self._safe_scan_manager.started.connect(self._on_safe_scan_started)
        self._safe_scan_manager.result_ready.connect(self._on_safe_scan_result)
        self._safe_scan_manager.error.connect(self._on_safe_scan_error)
        self._safe_scan_manager.finished.connect(self._on_safe_scan_finished)

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self._create_settings_panel())
        layout.addWidget(self._create_table())
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

        self.icmp_checkbox = QCheckBox(self._t("label_icmp"))
        self.icmp_checkbox.setChecked(True)
        self.port_checkbox = QCheckBox(self._t("label_ports"))
        self.port_checkbox.setChecked(True)
        self.os_checkbox = QCheckBox(self._t("label_os"))
        self.os_checkbox.setChecked(True)

        grid.addWidget(self.icmp_checkbox, 2, 0)
        grid.addWidget(self.port_checkbox, 2, 1)
        grid.addWidget(self.os_checkbox, 2, 2)

        self.start_button = QPushButton(self._t("start"))
        self.stop_button = QPushButton(self._t("stop"))
        self.stop_button.setEnabled(False)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)

        self.start_button.clicked.connect(self._on_start_clicked)
        self.stop_button.clicked.connect(self._on_stop_clicked)

        grid.addWidget(self.start_button, 3, 0)
        grid.addWidget(self.stop_button, 3, 1)
        grid.addWidget(self.progress_bar, 3, 2, 1, 2)

        return group

    def _create_table(self) -> QWidget:
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(
            [
                self._t("table_target"),
                self._t("table_alive"),
                self._t("table_ports"),
                self._t("table_os"),
                self._t("table_score"),
                self._t("table_priority"),
                self._t("table_errors"),
                self._t("table_safe_action"),
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

    def _create_summary_panel(self) -> QWidget:
        group = QGroupBox(self._t("summary_title"))
        layout = QVBoxLayout(group)
        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)
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

    def _collect_scan_modes(self) -> Set[ScanMode]:
        modes: Set[ScanMode] = set()
        if self.icmp_checkbox.isChecked():
            modes.add(ScanMode.ICMP)
        if self.port_checkbox.isChecked():
            modes.add(ScanMode.PORTS)
        if self.os_checkbox.isChecked():
            modes.add(ScanMode.OS)
        return modes

    def _on_start_clicked(self) -> None:
        targets = sanitize_targets(self.target_input.toPlainText())
        if not targets:
            QMessageBox.warning(
                self,
                self._t("missing_targets_title"),
                self._t("missing_targets_body"),
            )
            return
        modes = self._collect_scan_modes()
        if not modes:
            QMessageBox.warning(
                self,
                self._t("missing_modes_title"),
                self._t("missing_modes_body"),
            )
            return
        if not self._has_required_privileges(modes):
            self._show_privileged_hint()
            return
        self._target_count = len(targets)
        self._requested_host_estimate = self._estimate_requested_hosts(targets)
        self._summary_status = self._t("scanning")
        self._summary_has_error = False
        self._results.clear()
        self.table.setRowCount(0)
        self._update_summary()
        config = ScanConfig(targets=targets, scan_modes=modes)
        self._scan_manager.start(config)
        self._scan_active = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.statusBar().showMessage(self._t("scanning"))
        self._refresh_safe_scan_button_states()

    def _on_stop_clicked(self) -> None:
        self._scan_manager.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(self._t("scan_stopped"))
        self._summary_status = self._t("scan_stopped")
        self._scan_active = False
        self._update_summary()
        self._refresh_safe_scan_button_states()

    def _on_scan_started(self, total: int) -> None:
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(0)

    def _on_progress(self, done: int, total: int) -> None:
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(done)

    def _on_result(self, result: HostScanResult) -> None:
        self._results.append(result)
        sorting_enabled = self.table.isSortingEnabled()
        if sorting_enabled:
            self.table.setSortingEnabled(False)
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, self._make_item(result.target, Qt.AlignLeft))
        alive_text = self._t("alive_yes") if result.is_alive else self._t("alive_no")
        self.table.setItem(row, 1, self._make_item(alive_text, Qt.AlignCenter))
        ports_text = ", ".join(str(p) for p in result.open_ports)
        self.table.setItem(row, 2, self._make_item(ports_text, Qt.AlignLeft))
        os_text = result.os_guess
        if result.os_accuracy is not None:
            os_text = f"{os_text} ({result.os_accuracy}%)"
        self.table.setItem(row, 3, self._make_item(os_text, Qt.AlignLeft))
        self.table.setItem(row, 4, self._make_item(str(result.score), Qt.AlignRight))
        display_priority = self._priority_labels.get(result.priority, result.priority)
        priority_item = self._make_item(display_priority, Qt.AlignCenter)
        self.table.setItem(row, 5, priority_item)
        error_text = "\n".join(format_error_list(result.errors, self._language))
        self.table.setItem(row, 6, self._make_item(error_text, Qt.AlignLeft))
        self._add_safe_scan_button(row, result.target)
        self._apply_row_style(row, result.priority)
        if sorting_enabled:
            self.table.setSortingEnabled(True)
            if self._sort_column is not None:
                self.table.sortItems(self._sort_column, self._sort_order)
        self._update_summary()

    def _make_item(
        self, text: str, alignment: Qt.AlignmentFlag | None = None
    ) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        if alignment is not None:
            item.setTextAlignment(int(alignment | Qt.AlignVCenter))
        return item

    def _apply_row_style(self, row: int, priority: str) -> None:
        color = PRIORITY_COLORS.get(priority)
        if not color:
            return
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(color)

    def _add_safe_scan_button(self, row: int, target: str) -> None:
        button = QPushButton(self._t("safe_scan_button"))
        button.clicked.connect(partial(self._on_safe_scan_button_clicked, target))
        button.setEnabled(self._safe_scan_buttons_enabled())
        self.table.setCellWidget(row, SAFE_SCAN_COLUMN_INDEX, button)

    def _safe_scan_buttons_enabled(self) -> bool:
        return (not self._scan_active) and (not self._safe_scan_active)

    def _refresh_safe_scan_button_states(self) -> None:
        enabled = self._safe_scan_buttons_enabled()
        for button in self._iter_safe_scan_buttons():
            button.setEnabled(enabled)

    def _iter_safe_scan_buttons(self):
        for row in range(self.table.rowCount()):
            widget = self.table.cellWidget(row, SAFE_SCAN_COLUMN_INDEX)
            if isinstance(widget, QPushButton):
                yield widget

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
        self.safe_progress_bar.setValue(0)
        self.safe_progress_bar.setFormat("%p%")
        self._update_safe_progress_label(0.0)
        self._ensure_safe_progress_visible()
        if not self._safe_progress_timer.isActive():
            self._safe_progress_timer.start(SAFE_PROGRESS_UPDATE_MS)

    def _on_safe_progress_tick(self) -> None:
        if not self._safe_scan_active or self._safe_scan_elapsed_start is None:
            return
        elapsed = time.monotonic() - self._safe_scan_elapsed_start
        expected = self._safe_scan_expected_duration
        if expected <= 0:
            expected = SAFE_SCAN_DEFAULT_DURATION
        fraction = min((elapsed / expected) * 0.9, 0.9)
        progress = int(fraction * 100)
        self.safe_progress_bar.setValue(progress)
        self._update_safe_progress_label(elapsed)

    def _update_safe_progress_label(self, elapsed_seconds: float) -> None:
        remaining = max(self._safe_scan_expected_duration - elapsed_seconds, 0)
        mins, secs = divmod(int(round(remaining)), 60)
        eta = f"{mins:02d}:{secs:02d}"
        avg_seconds = max(self._safe_scan_expected_duration, SAFE_SCAN_DEFAULT_DURATION)
        self.safe_progress_label.setText(
            self._t("safe_scan_progress_running").format(eta=eta, avg=int(round(avg_seconds)))
        )

    def _complete_safe_progress(self, duration: float | None) -> None:
        self._safe_progress_timer.stop()
        self.safe_progress_bar.setValue(100)
        if duration is not None:
            self.safe_progress_label.setText(
                self._t("safe_scan_progress_complete").format(seconds=int(round(duration)))
            )
        else:
            self.safe_progress_label.setText(self._t("safe_scan_progress_finished"))
        QTimer.singleShot(SAFE_PROGRESS_VISIBILITY_MS, self._hide_safe_progress)
        self._safe_scan_elapsed_start = None

    def _record_safe_scan_duration(self, duration: float) -> None:
        self._safe_scan_history.append(duration)
        if len(self._safe_scan_history) > SAFE_SCAN_HISTORY_LIMIT:
            self._safe_scan_history.pop(0)
        average = sum(self._safe_scan_history) / len(self._safe_scan_history)
        self._safe_scan_expected_duration = max(SAFE_SCAN_DEFAULT_DURATION, average)

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

    def _on_safe_scan_button_clicked(self, target: str) -> None:
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
        self._safe_scan_manager.start(target)

    def _on_safe_scan_started(self, target: str) -> None:
        self._safe_scan_active = True
        self._safe_scan_target = target
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(
            self._t("safe_scan_status_running").format(target=target)
        )
        self._refresh_safe_scan_button_states()
        self._start_safe_progress()

    def _on_safe_scan_result(self, report: SafeScanReport) -> None:
        dialog = SafeScanDialog(self, report, self._language)
        dialog.exec()
        if dialog.saved_path:
            self.statusBar().showMessage(
                self._t("safe_scan_save_success_body").format(path=dialog.saved_path)
            )

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
        target = self._safe_scan_target or ""
        self._safe_scan_target = None
        if not self._scan_active:
            self.start_button.setEnabled(True)
        self.stop_button.setEnabled(self._scan_active)
        if not self._scan_active:
            finished_message = self._t("safe_scan_status_finished").format(target=target)
            self.statusBar().showMessage(finished_message)
        self._refresh_safe_scan_button_states()
        self._complete_safe_progress(duration)
        if duration is not None:
            self._record_safe_scan_duration(duration)

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

    def _on_finished(self) -> None:
        self._scan_active = False
        self.start_button.setEnabled(not self._safe_scan_active)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(self._t("scan_finished"))
        if not self._summary_has_error:
            if self._results:
                self._summary_status = self._t("scan_finished")
            else:
                self._summary_status = self._t("summary_status_no_hosts")
        self._update_summary()
        self._refresh_safe_scan_button_states()

    def _t(self, key: str) -> str:
        return translate(key, self._language)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._scan_manager.stop()
        self._safe_scan_manager.stop()
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
