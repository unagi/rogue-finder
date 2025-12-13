"""Summary and advisory panel widgets."""
from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import QGroupBox, QLabel, QVBoxLayout

Translator = Callable[[str], str]


class SummaryPanel(QGroupBox):
    def __init__(self, translator: Translator, parent=None):
        super().__init__(translator("summary_title"), parent)
        self._t = translator
        self._summary_label = QLabel("")
        self._summary_label.setWordWrap(True)
        self._mac_limited_label = QLabel("")
        self._mac_limited_label.setWordWrap(True)
        font = self._mac_limited_label.font()
        font.setItalic(True)
        self._mac_limited_label.setFont(font)
        self._mac_limited_label.setVisible(False)
        layout = QVBoxLayout(self)
        layout.addWidget(self._summary_label)
        layout.addWidget(self._mac_limited_label)

    def update_summary(
        self,
        *,
        target_count: int,
        requested_hosts: int,
        discovered_hosts: int,
        alive_hosts: int,
        status: str,
    ) -> None:
        summary_text = self._t("summary_template").format(
            targets=target_count,
            requested=requested_hosts,
            discovered=discovered_hosts,
            alive=alive_hosts,
            status=status,
        )
        self._summary_label.setText(summary_text)

    def set_mac_limited(self, limited: bool, message: str) -> None:
        if limited:
            self._mac_limited_label.setText(message)
            self._mac_limited_label.setVisible(True)
        else:
            self._mac_limited_label.clear()
            self._mac_limited_label.setVisible(False)
