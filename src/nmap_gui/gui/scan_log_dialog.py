"""Modeless dialog that renders streaming stdout/stderr for discovery scans."""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QVBoxLayout,
)

from ..i18n import translate
from ..models import ScanLogEvent, ScanMode
from ..utils import slugify_filename_component


class ScanLogDialog(QDialog):
    """Modeless dialog that renders streaming stdout/stderr for discovery scans."""

    def __init__(self, parent, language: str):
        super().__init__(parent)
        self._language = language
        self._logs: dict[str, list[str]] = {}
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
        phase_label = self._phase_label(event.phase)
        self._status_label.setText(
            self._t("log_dialog_running").format(target=target, phase=phase_label)
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
        if self._target_combo.findText(target, Qt.MatchExactly) == -1:
            self._target_combo.addItem(target)

    def _set_current_target(self, target: str) -> None:
        index = self._target_combo.findText(target, Qt.MatchExactly)
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
        filename = (
            f"scan-log_{slugify_filename_component(target, fallback='target')}_{timestamp}.txt"
        )
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

    def closeEvent(self, event):  # type: ignore[override]
        event.ignore()
        self.hide()
