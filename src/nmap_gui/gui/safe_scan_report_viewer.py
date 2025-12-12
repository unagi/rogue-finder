"""Embedded diagnostics report viewer."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QVBoxLayout,
)

from ..models import SafeScanReport
from .safe_scan_report_formatter import build_default_filename, build_report_text, build_status_text


class SafeScanReportViewer(QGroupBox):
    """Inline widget that displays stored SafeScanReport data."""

    def __init__(self, translator, language: str, parent=None):
        super().__init__(translator("diagnostics_viewer_title"), parent)
        self._t = translator
        self._language = language
        self._current_report: SafeScanReport | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        self._target_label = QLabel(self._t("diagnostics_viewer_target_none"))
        header.addWidget(self._target_label)
        header.addStretch()
        self._save_button = QPushButton(self._t("safe_scan_save_button"))
        self._save_button.setEnabled(False)
        self._save_button.clicked.connect(self._save_current_report)
        header.addWidget(self._save_button)
        layout.addLayout(header)

        self._status_label = QLabel("")
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

        self._empty_label = QLabel(self._t("diagnostics_viewer_placeholder"))
        self._empty_label.setWordWrap(True)
        layout.addWidget(self._empty_label)

        self._text_edit = QPlainTextEdit()
        self._text_edit.setReadOnly(True)
        self._text_edit.setVisible(False)
        layout.addWidget(self._text_edit)

    def show_report(self, report: SafeScanReport) -> None:
        self._current_report = report
        self._target_label.setText(
            self._t("diagnostics_viewer_target").format(target=report.target)
        )
        self._status_label.setText(build_status_text(report, self._language))
        self._text_edit.setPlainText(build_report_text(report, self._language))
        self._text_edit.setVisible(True)
        self._empty_label.setVisible(False)
        self._save_button.setEnabled(True)

    def clear_report(self) -> None:
        self._current_report = None
        self._target_label.setText(self._t("diagnostics_viewer_target_none"))
        self._status_label.clear()
        self._text_edit.clear()
        self._text_edit.setVisible(False)
        self._empty_label.setVisible(True)
        self._save_button.setEnabled(False)

    def current_target(self) -> str | None:
        if self._current_report:
            return self._current_report.target
        return None

    def _save_current_report(self) -> None:
        if not self._current_report:
            return
        suggested_name = build_default_filename(self._current_report)
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._t("safe_scan_save_dialog"),
            suggested_name,
            self._t("safe_scan_save_filter"),
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(build_report_text(self._current_report, self._language))
        QMessageBox.information(
            self,
            self._t("safe_scan_save_success_title"),
            self._t("safe_scan_save_success_body").format(path=path),
        )
