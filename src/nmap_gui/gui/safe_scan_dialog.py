"""Safe scan report dialog."""
from __future__ import annotations

from datetime import datetime
from typing import List

from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QMessageBox,
    QDialog,
    QDialogButtonBox,
    QPlainTextEdit,
    QVBoxLayout,
)

from ..i18n import format_error_record, translate
from ..models import SafeScanReport
from ..utils import slugify_filename_component


class SafeScanDialog(QDialog):
    """Modal dialog that shows the safe script report and enables exporting."""

    def __init__(self, parent, report: SafeScanReport, language: str):
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
