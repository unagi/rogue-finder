"""Export toolbar widget."""
from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QWidget

Translator = Callable[[str], str]


class ExportToolbar(QWidget):
    export_csv_requested = Signal()
    export_json_requested = Signal()

    def __init__(self, translator: Translator, parent=None):
        super().__init__(parent)
        self._t = translator
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.addStretch()
        csv_btn = QPushButton(self._t("export_csv"))
        json_btn = QPushButton(self._t("export_json"))
        csv_btn.clicked.connect(self.export_csv_requested)
        json_btn.clicked.connect(self.export_json_requested)
        layout.addWidget(csv_btn)
        layout.addWidget(json_btn)
