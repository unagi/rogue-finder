"""Safe scan report dialog."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QMessageBox,
    QDialog,
    QDialogButtonBox,
    QPlainTextEdit,
    QVBoxLayout,
)

from ..i18n import translate
from ..models import SafeScanReport
from .safe_scan_report_formatter import build_default_filename, build_report_text, build_status_text


class SafeScanDialog(QDialog):
    """Modal dialog that shows the safe script report and enables exporting."""

    def __init__(self, parent, report: SafeScanReport, language: str):
        super().__init__(parent)
        self._report = report
        self._language = language
        self.saved_path: str | None = None
        self._report_text = build_report_text(report, language)
        self.setWindowTitle(
            translate("safe_scan_dialog_title", language).format(target=report.target)
        )
        layout = QVBoxLayout(self)
        self._status_label = QLabel(build_status_text(report, language))
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

    def _save_report(self) -> None:
        suggested_name = build_default_filename(self._report)
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

    def _label(self, key: str) -> str:
        return translate(key, self._language)
