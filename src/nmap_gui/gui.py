"""PySide6 GUI for the Nmap discovery & rating application."""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path
from typing import List, Set

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
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
)

from .exporters import export_csv, export_json
from .i18n import detect_language, format_error_list, format_error_record, translate
from .models import ErrorRecord, HostScanResult, ScanConfig, ScanMode, sanitize_targets
from .scan_manager import ScanManager


PRIORITY_COLORS = {
    "High": QColor(255, 204, 204),
    "Medium": QColor(255, 240, 210),
    "Low": QColor(210, 235, 255),
}


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
        self._sort_column: int | None = None
        self._sort_order = Qt.AscendingOrder
        self._setup_scan_manager()
        self._build_ui()

    def _setup_scan_manager(self) -> None:
        self._scan_manager.started.connect(self._on_scan_started)
        self._scan_manager.progress.connect(self._on_progress)
        self._scan_manager.result_ready.connect(self._on_result)
        self._scan_manager.error.connect(self._on_error)
        self._scan_manager.finished.connect(self._on_finished)

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self._create_settings_panel())
        layout.addWidget(self._create_table())
        layout.addLayout(self._create_export_bar())
        self.setCentralWidget(central)
        self.statusBar().showMessage(self._t("ready"))

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
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            [
                self._t("table_target"),
                self._t("table_alive"),
                self._t("table_ports"),
                self._t("table_os"),
                self._t("table_score"),
                self._t("table_priority"),
                self._t("table_errors"),
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
        self._results.clear()
        self.table.setRowCount(0)
        config = ScanConfig(targets=targets, scan_modes=modes)
        self._scan_manager.start(config)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.statusBar().showMessage(self._t("scanning"))

    def _on_stop_clicked(self) -> None:
        self._scan_manager.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(self._t("scan_stopped"))

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
        self._apply_row_style(row, result.priority)
        if sorting_enabled:
            self.table.setSortingEnabled(True)
            if self._sort_column is not None:
                self.table.sortItems(self._sort_column, self._sort_order)

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

    def _on_error(self, payload) -> None:
        if isinstance(payload, ErrorRecord):
            message = format_error_record(payload, self._language)
        else:
            message = str(payload)
        QMessageBox.critical(self, self._t("scan_error_title"), message)
        self.statusBar().showMessage(message)

    def _on_finished(self) -> None:
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(self._t("scan_finished"))

    def _t(self, key: str) -> str:
        return translate(key, self._language)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._scan_manager.stop()
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
