"""Configuration editor dialog with YAML validation and highlighting."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

import yaml
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QSyntaxHighlighter
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..config import (
    AppSettings,
    config_file_path,
    get_settings,
    load_settings,
    merge_with_defaults,
    reset_settings_cache,
    write_settings,
)

Translator = Callable[[str], str]


class ConfigEditorDialog(QDialog):
    """Simple YAML-based configuration editor."""

    settingsUpdated = Signal(AppSettings)

    def __init__(
        self,
        translator: Translator,
        parent: QWidget | None = None,
        *,
        config_path: Path | str | None = None,
    ) -> None:
        super().__init__(parent)
        self._t = translator
        self._path = config_file_path(config_path)
        self._dirty = False
        self._suppress_changes = False
        self._build_ui()
        self.reload_from_disk()

    def _build_ui(self) -> None:
        self.setWindowTitle(self._t("config_editor_title"))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        description = QLabel(self._t("config_editor_description"))
        description.setWordWrap(True)
        layout.addWidget(description)

        self._editor = QPlainTextEdit()
        font = QFont("Courier New")
        font.setStyleHint(QFont.Monospace)
        font.setPointSize(10)
        self._editor.setFont(font)
        self._editor.setTabStopDistance(4 * self._editor.fontMetrics().horizontalAdvance(" "))
        self._editor.textChanged.connect(self._on_text_changed)
        layout.addWidget(self._editor)
        self._highlighter = _YamlHighlighter(self._editor.document())

        self._status_label = QLabel("")
        self._status_label.setAlignment(Qt.AlignLeft)
        layout.addWidget(self._status_label)

        button_row = QHBoxLayout()
        button_row.setSpacing(6)
        self._reload_button = QPushButton(self._t("config_editor_reload_button"))
        self._reload_button.clicked.connect(self.reload_from_disk)
        button_row.addWidget(self._reload_button)
        self._save_button = QPushButton(self._t("config_editor_save_button"))
        self._save_button.clicked.connect(self._save_changes)
        button_row.addWidget(self._save_button)
        self._close_button = QPushButton(self._t("config_editor_close_button"))
        self._close_button.clicked.connect(self.close)
        button_row.addStretch()
        button_row.addWidget(self._close_button)
        layout.addLayout(button_row)

    def _set_status(self, message: str) -> None:
        self._status_label.setText(message)

    def _on_text_changed(self) -> None:
        if self._suppress_changes:
            return
        self._dirty = True

    def reload_from_disk(self) -> None:
        try:
            settings = load_settings(self._path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self,
                self._t("config_editor_yaml_error_title"),
                self._t("config_editor_yaml_error_body").format(error=str(exc)),
            )
            return
        text = yaml.safe_dump(settings.raw, sort_keys=False)
        self._apply_text(text)
        self._dirty = False
        self._set_status(
            self._t("config_editor_status_loaded").format(path=str(self._path))
        )

    def _apply_text(self, text: str) -> None:
        self._suppress_changes = True
        try:
            self._editor.setPlainText(text)
        finally:
            self._suppress_changes = False

    def _parse_yaml(self) -> dict:
        try:
            data = yaml.safe_load(self._editor.toPlainText()) or {}
        except yaml.YAMLError as exc:
            raise ValueError(str(exc)) from exc
        if not isinstance(data, dict):
            raise ValueError(self._t("config_editor_validation_error"))
        return data

    def _save_changes(self) -> None:
        try:
            parsed = self._parse_yaml()
        except ValueError as exc:
            QMessageBox.warning(
                self,
                self._t("config_editor_yaml_error_title"),
                self._t("config_editor_yaml_error_body").format(error=str(exc)),
            )
            return
        merged = merge_with_defaults(parsed)
        serialized = yaml.safe_dump(merged, sort_keys=False)
        try:
            success = write_settings(merged, self._path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self,
                self._t("config_editor_save_failed_title"),
                self._t("config_editor_save_failed_body").format(error=str(exc)),
            )
            return
        if not success:
            QMessageBox.critical(
                self,
                self._t("config_editor_save_failed_title"),
                self._t("config_editor_save_failed_body").format(error=self._path),
            )
            return
        self._apply_text(serialized)
        self._dirty = False
        self._set_status(
            self._t("config_editor_status_saved").format(path=str(self._path))
        )
        reset_settings_cache()
        new_settings = get_settings()
        self.settingsUpdated.emit(new_settings)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._dirty:
            reply = QMessageBox.question(
                self,
                self._t("config_editor_unsaved_title"),
                self._t("config_editor_unsaved_body"),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                event.ignore()
                return
        super().closeEvent(event)


class _YamlHighlighter(QSyntaxHighlighter):
    """Very small YAML syntax highlighter."""

    def __init__(self, document) -> None:
        super().__init__(document)
        self._comment_pattern = re.compile(r"#.*")
        self._key_pattern = re.compile(r"(^|\s)([A-Za-z0-9_\"']+)(?=\s*:)")
        self._number_pattern = re.compile(r"(?<![\w-])(-?\d+(?:\.\d+)?)")
        self._bool_pattern = re.compile(r"\b(true|false|null|True|False|Null)\b")
        self._comment_format = QTextCharFormat()
        self._comment_format.setForeground(QColor("#6a9955"))
        self._key_format = QTextCharFormat()
        self._key_format.setForeground(QColor("#569cd6"))
        self._key_format.setFontWeight(QFont.Bold)
        self._number_format = QTextCharFormat()
        self._number_format.setForeground(QColor("#b5cea8"))
        self._bool_format = QTextCharFormat()
        self._bool_format.setForeground(QColor("#c586c0"))

    def highlightBlock(self, text: str) -> None:  # type: ignore[override]
        for pattern, fmt in (
            (self._comment_pattern, self._comment_format),
            (self._key_pattern, self._key_format),
            (self._number_pattern, self._number_format),
            (self._bool_pattern, self._bool_format),
        ):
            for match in pattern.finditer(text):
                start = match.start(2) if pattern is self._key_pattern else match.start()
                end = match.end(2) if pattern is self._key_pattern else match.end()
                length = max(0, end - start)
                if length > 0:
                    self.setFormat(start, length, fmt)
