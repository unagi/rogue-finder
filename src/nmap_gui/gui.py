"""PySide6 GUI for the Nmap discovery & rating application."""
from __future__ import annotations

from typing import List, Set

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
from .models import HostScanResult, ScanConfig, ScanMode, sanitize_targets
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
        self.setWindowTitle("Nmap Discovery & Rating")
        self.resize(1000, 700)
        self._results: List[HostScanResult] = []
        self._scan_manager = ScanManager()
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
        self.statusBar().showMessage("Ready")

    def _create_settings_panel(self) -> QWidget:
        group = QGroupBox("Scan Settings")
        grid = QGridLayout(group)

        grid.addWidget(QLabel("Targets (IP / CIDR / hostname)"), 0, 0)
        self.target_input = QPlainTextEdit()
        self.target_input.setPlaceholderText("192.168.0.0/24\n10.0.0.5\nserver.local")
        self.target_input.setFixedHeight(80)
        grid.addWidget(self.target_input, 1, 0, 1, 4)

        self.icmp_checkbox = QCheckBox("ICMP")
        self.icmp_checkbox.setChecked(True)
        self.port_checkbox = QCheckBox("Ports")
        self.port_checkbox.setChecked(True)
        self.os_checkbox = QCheckBox("OS")
        self.os_checkbox.setChecked(True)

        grid.addWidget(self.icmp_checkbox, 2, 0)
        grid.addWidget(self.port_checkbox, 2, 1)
        grid.addWidget(self.os_checkbox, 2, 2)

        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
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
            ["Target", "Alive", "Ports", "OS", "Score", "Priority", "Errors"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        return self.table

    def _create_export_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.addStretch()
        export_csv_btn = QPushButton("Export CSV")
        export_json_btn = QPushButton("Export JSON")
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
            QMessageBox.warning(self, "Missing targets", "Please enter at least one target")
            return
        modes = self._collect_scan_modes()
        if not modes:
            QMessageBox.warning(self, "Missing scan modes", "Select at least one scan mode")
            return
        self._results.clear()
        self.table.setRowCount(0)
        config = ScanConfig(targets=targets, scan_modes=modes)
        self._scan_manager.start(config)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.statusBar().showMessage("Scanning...")

    def _on_stop_clicked(self) -> None:
        self._scan_manager.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage("Scan stopped")

    def _on_scan_started(self, total: int) -> None:
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(0)

    def _on_progress(self, done: int, total: int) -> None:
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(done)

    def _on_result(self, result: HostScanResult) -> None:
        self._results.append(result)
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(result.target))
        self.table.setItem(row, 1, QTableWidgetItem("Yes" if result.is_alive else "No"))
        self.table.setItem(row, 2, QTableWidgetItem(", ".join(str(p) for p in result.open_ports)))
        os_text = result.os_guess
        if result.os_accuracy is not None:
            os_text = f"{os_text} ({result.os_accuracy}%)"
        self.table.setItem(row, 3, QTableWidgetItem(os_text))
        self.table.setItem(row, 4, QTableWidgetItem(str(result.score)))
        priority_item = QTableWidgetItem(result.priority)
        self.table.setItem(row, 5, priority_item)
        self.table.setItem(row, 6, QTableWidgetItem("; ".join(result.errors)))
        self._apply_row_style(row, result.priority)

    def _apply_row_style(self, row: int, priority: str) -> None:
        color = PRIORITY_COLORS.get(priority)
        if not color:
            return
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(color)

    def _on_error(self, message: str) -> None:
        QMessageBox.critical(self, "Scan error", message)
        self.statusBar().showMessage(message)

    def _on_finished(self) -> None:
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage("Scan finished")

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._scan_manager.stop()
        super().closeEvent(event)

    def _export_csv(self) -> None:
        if not self._results:
            QMessageBox.information(self, "No results", "Scan results are empty")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export CSV",
            "scan_results.csv",
            "CSV Files (*.csv)",
        )
        if not path:
            return
        export_csv(path, self._results)
        self.statusBar().showMessage(f"CSV exported: {path}")

    def _export_json(self) -> None:
        if not self._results:
            QMessageBox.information(self, "No results", "Scan results are empty")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export JSON",
            "scan_results.json",
            "JSON Files (*.json)",
        )
        if not path:
            return
        export_json(path, self._results)
        self.statusBar().showMessage(f"JSON exported: {path}")
