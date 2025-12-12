"""Scan controls panel helpers."""
from __future__ import annotations

from enum import Enum, auto
from typing import Callable

from PySide6.QtCore import QEvent, Signal
from PySide6.QtWidgets import QGridLayout, QGroupBox, QLabel, QPushButton, QPlainTextEdit, QSizePolicy

Translator = Callable[[str], str]


class ScanControlsState(Enum):
    IDLE = auto()
    SCANNING = auto()
    SAFE_RUNNING = auto()


class ScanControlsPanel(QGroupBox):
    """Target input, action buttons, and log controls."""

    start_requested = Signal()
    stop_requested = Signal()
    clear_requested = Signal()
    log_requested = Signal()
    config_editor_requested = Signal()
    targets_changed = Signal()

    def __init__(self, translator: Translator, parent=None):
        super().__init__(translator("scan_settings"), parent)
        self._t = translator
        self._build_ui()
        self._apply_compact_height()
        self.set_state(ScanControlsState.IDLE)

    def _build_ui(self) -> None:
        grid = QGridLayout(self)
        grid.setContentsMargins(12, 12, 12, 8)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)

        grid.addWidget(QLabel(self._t("targets_label")), 0, 0)
        self._target_input = QPlainTextEdit()
        self._target_input.setPlaceholderText(self._t("targets_placeholder"))
        self._target_input.setFixedHeight(64)
        self._target_input.document().setDocumentMargin(4)
        self._target_input.textChanged.connect(self.targets_changed)
        grid.addWidget(self._target_input, 1, 0, 1, 4)

        self._start_button = QPushButton(self._t("fast_scan_button"))
        self._stop_button = QPushButton(self._t("stop"))
        self._clear_button = QPushButton(self._t("clear_results_button"))
        self._log_button = QPushButton(self._t("open_log_button"))
        self._config_button = QPushButton(self._t("config_editor_button"))
        self._start_button.clicked.connect(self.start_requested)
        self._stop_button.clicked.connect(self.stop_requested)
        self._clear_button.clicked.connect(self.clear_requested)
        self._log_button.clicked.connect(self.log_requested)
        self._config_button.clicked.connect(self.config_editor_requested)

        grid.addWidget(self._start_button, 2, 0)
        grid.addWidget(self._stop_button, 2, 1)
        grid.addWidget(self._clear_button, 2, 2)
        grid.addWidget(self._log_button, 2, 3)
        grid.addWidget(self._config_button, 2, 4)

        self._log_button.setEnabled(False)
        self._config_button.setEnabled(True)

    def event(self, event):  # type: ignore[override]
        if event.type() in (QEvent.FontChange, QEvent.ApplicationFontChange, QEvent.LayoutRequest):
            self._update_compact_height()
        return super().event(event)

    def targets_text(self) -> str:
        return self._target_input.toPlainText()

    def set_targets_text(self, text: str) -> None:
        self._target_input.setPlainText(text)

    def set_state(self, state: ScanControlsState) -> None:
        if state == ScanControlsState.IDLE:
            self._start_button.setEnabled(True)
            self._stop_button.setEnabled(False)
        elif state == ScanControlsState.SCANNING:
            self._start_button.setEnabled(False)
            self._stop_button.setEnabled(True)
        elif state == ScanControlsState.SAFE_RUNNING:
            self._start_button.setEnabled(False)
            self._stop_button.setEnabled(False)

    def set_clear_enabled(self, enabled: bool) -> None:
        self._clear_button.setEnabled(enabled)

    def set_log_enabled(self, enabled: bool) -> None:
        self._log_button.setEnabled(enabled)

    def focus_targets(self) -> None:
        self._target_input.setFocus()

    def _apply_compact_height(self) -> None:
        policy = self.sizePolicy()
        policy.setVerticalPolicy(QSizePolicy.Fixed)
        self.setSizePolicy(policy)
        self._update_compact_height()

    def _update_compact_height(self) -> None:
        hint = self.sizeHint().height()
        if hint > 0 and hint != self.maximumHeight():
            self.setFixedHeight(hint)
