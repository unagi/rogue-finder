from __future__ import annotations

from typing import Callable, Dict, Iterable, Sequence, Set

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .i18n import format_error_list
from .models import HostScanResult


TARGET_COLUMN_INDEX = 0
ALIVE_COLUMN_INDEX = 1
PORTS_COLUMN_INDEX = 2
OS_COLUMN_INDEX = 3
SCORE_COLUMN_INDEX = 4
PRIORITY_COLUMN_INDEX = 5
ERROR_COLUMN_INDEX = 6
ADVANCED_COLUMN_INDEX = 7
OS_OPTION_COLUMN_INDEX = 8
SAFETY_COLUMN_INDEX = 9
DIAGNOSTICS_COLUMN_INDEX = 10
DEFAULT_PRIORITY_COLORS = {
    "High": QColor(255, 204, 204),
    "Medium": QColor(255, 240, 210),
    "Low": QColor(210, 235, 255),
}


class ResultGrid(QObject):
    """Encapsulates the discovery results table and selection controls."""

    selectionChanged = Signal()
    runAdvancedRequested = Signal()
    runSafetyRequested = Signal()

    def __init__(
        self,
        *,
        translator: Callable[[str], str],
        language: str,
        priority_labels: Dict[str, str],
        priority_colors: Dict[str, str],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._t = translator
        self._language = language
        self._priority_labels = priority_labels
        self._priority_color_overrides = priority_colors
        self._widget = QWidget(parent)
        self._advanced_selection: Set[str] = set()
        self._os_selection: Set[str] = set()
        self._safety_selection: Set[str] = set()
        self._result_index: Dict[str, int] = {}
        self._row_checkboxes: Dict[str, Dict[str, QCheckBox]] = {}
        self._os_selection_allowed = True
        self._os_tooltip = ""
        self._sort_column: int | None = None
        self._sort_order = Qt.AscendingOrder
        self._build_widget()

    def widget(self) -> QWidget:
        return self._widget

    def set_selections(
        self,
        *,
        advanced: Iterable[str],
        os_targets: Iterable[str],
        safety: Iterable[str],
        emit_signal: bool = True,
    ) -> None:
        self._advanced_selection = set(advanced)
        self._os_selection = set(os_targets)
        self._safety_selection = set(safety)
        self._sync_select_all_checkboxes()
        self._refresh_os_checkbox_states()
        if emit_signal:
            self.selectionChanged.emit()

    def advanced_targets(self) -> Set[str]:
        return set(self._advanced_selection)

    def os_targets(self) -> Set[str]:
        return set(self._os_selection)

    def safety_targets(self) -> Set[str]:
        return set(self._safety_selection)

    def has_advanced_selection(self) -> bool:
        return bool(self._advanced_selection)

    def has_safety_selection(self) -> bool:
        return bool(self._safety_selection)

    def reset(self, *, emit_signal: bool = True) -> None:
        self._result_index.clear()
        self._row_checkboxes.clear()
        self._advanced_selection.clear()
        self._os_selection.clear()
        self._safety_selection.clear()
        self._table.setRowCount(0)
        self._sync_select_all_checkboxes()
        self._update_select_all_enabled()
        if emit_signal:
            self.selectionChanged.emit()

    def update_result(self, result: HostScanResult, *, allow_sort_restore: bool = True) -> None:
        target = result.target
        row = self._result_index.get(target)
        if row is None:
            self._insert_row(result, allow_sort_restore=allow_sort_restore)
        else:
            self._populate_row(row, result)

    def clear_completed_advanced_selection(self, targets: Sequence[str]) -> None:
        changed = False
        for target in targets:
            if target in self._advanced_selection:
                self._advanced_selection.discard(target)
                changed = True
            if target in self._os_selection:
                self._os_selection.discard(target)
            widgets = self._row_checkboxes.get(target, {})
            adv_cb = widgets.get("advanced")
            if adv_cb:
                adv_cb.blockSignals(True)
                adv_cb.setChecked(False)
                adv_cb.blockSignals(False)
            os_cb = widgets.get("os")
            if os_cb:
                os_cb.blockSignals(True)
                os_cb.setChecked(False)
                os_cb.setEnabled(False)
                os_cb.blockSignals(False)
        self._sync_select_all_checkboxes()
        self._refresh_os_checkbox_states()
        if changed:
            self.selectionChanged.emit()

    def clear_safety_selection_for_target(self, target: str) -> None:
        if target not in self._safety_selection:
            return
        self._safety_selection.discard(target)
        checkbox = self._row_checkboxes.get(target, {}).get("safety")
        if checkbox:
            checkbox.blockSignals(True)
            checkbox.setChecked(False)
            checkbox.blockSignals(False)
        self._sync_select_all_checkboxes()
        self.selectionChanged.emit()

    def set_run_buttons_enabled(self, *, advanced: bool, safety: bool) -> None:
        self._run_advanced_button.setEnabled(advanced)
        self._run_safety_button.setEnabled(safety)

    def set_os_selection_allowed(self, allowed: bool, tooltip: str | None = None) -> None:
        self._os_selection_allowed = allowed
        if tooltip is not None:
            self._os_tooltip = tooltip
        self._update_os_select_all_enabled()
        self._refresh_os_checkbox_states()

    def has_rows(self) -> bool:
        return bool(self._result_index)

    def _build_widget(self) -> None:
        layout = QVBoxLayout(self._widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addLayout(self._create_action_bar())
        layout.addWidget(self._create_table())

    def _create_action_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.addWidget(QLabel(self._t("advanced_select_label")))
        self._advanced_select_all_checkbox = QCheckBox(self._t("select_all"))
        self._advanced_select_all_checkbox.stateChanged.connect(
            lambda state: self._toggle_all_checkboxes("advanced", state)
        )
        bar.addWidget(self._advanced_select_all_checkbox)
        self._os_select_all_checkbox = QCheckBox(self._t("select_all_os"))
        self._os_select_all_checkbox.stateChanged.connect(
            lambda state: self._toggle_all_checkboxes("os", state)
        )
        bar.addWidget(self._os_select_all_checkbox)
        self._run_advanced_button = QPushButton(self._t("run_advanced_button"))
        self._run_advanced_button.setEnabled(False)
        self._run_advanced_button.clicked.connect(lambda: self.runAdvancedRequested.emit())
        bar.addWidget(self._run_advanced_button)
        bar.addSpacing(20)
        bar.addWidget(QLabel(self._t("safety_select_label")))
        self._safety_select_all_checkbox = QCheckBox(self._t("select_all"))
        self._safety_select_all_checkbox.stateChanged.connect(
            lambda state: self._toggle_all_checkboxes("safety", state)
        )
        bar.addWidget(self._safety_select_all_checkbox)
        self._run_safety_button = QPushButton(self._t("run_safety_button"))
        self._run_safety_button.setEnabled(False)
        self._run_safety_button.clicked.connect(lambda: self.runSafetyRequested.emit())
        bar.addWidget(self._run_safety_button)
        bar.addStretch()
        return bar

    def _create_table(self) -> QWidget:
        self._table = QTableWidget(0, 11)
        self._table.setHorizontalHeaderLabels(
            [
                self._t("table_target"),
                self._t("table_alive"),
                self._t("table_ports"),
                self._t("table_os"),
                self._t("table_score"),
                self._t("table_priority"),
                self._t("table_errors"),
                self._t("table_advanced"),
                self._t("table_os_option"),
                self._t("table_safety"),
                self._t("table_diagnostics_status"),
            ]
        )
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSortIndicatorShown(False)
        header.setSectionsClickable(True)
        header.sectionClicked.connect(self._handle_sort_request)
        self._table.setSortingEnabled(False)
        self._table.setWordWrap(False)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        return self._table

    def _toggle_all_checkboxes(self, kind: str, state: int) -> None:
        checked = Qt.CheckState(state) == Qt.CheckState.Checked
        if not self._row_checkboxes:
            return
        targets = list(self._row_checkboxes.keys())
        if kind == "os" and checked:
            targets = [target for target in targets if target in self._advanced_selection]
        for target in targets:
            checkbox = self._row_checkboxes.get(target, {}).get(kind)
            if checkbox is None:
                continue
            checkbox.blockSignals(True)
            checkbox.setChecked(checked)
            checkbox.blockSignals(False)
            self._on_row_checkbox_changed(kind, target, Qt.Checked if checked else Qt.Unchecked)
        self._sync_select_all_checkboxes()

    def _insert_row(self, result: HostScanResult, *, allow_sort_restore: bool) -> None:
        sorting_enabled = self._table.isSortingEnabled()
        if sorting_enabled:
            self._table.setSortingEnabled(False)
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._populate_row(row, result)
        self._attach_row_checkboxes(row, result.target)
        self._result_index[result.target] = row
        self._update_select_all_enabled()
        if sorting_enabled:
            self._table.setSortingEnabled(True)
            if allow_sort_restore and self._sort_column is not None:
                self._table.sortItems(self._sort_column, self._sort_order)
                self._rebuild_row_index_from_table()

    def _populate_row(self, row: int, result: HostScanResult) -> None:
        self._table.setItem(row, TARGET_COLUMN_INDEX, self._make_item(result.target, Qt.AlignLeft))
        alive_text = self._t("alive_yes") if result.is_alive else self._t("alive_no")
        self._table.setItem(row, ALIVE_COLUMN_INDEX, self._make_item(alive_text, Qt.AlignCenter))
        ports_text = ", ".join(str(p) for p in result.open_ports)
        self._table.setItem(row, PORTS_COLUMN_INDEX, self._make_item(ports_text, Qt.AlignLeft))
        os_text = result.os_guess
        if result.os_accuracy is not None:
            os_text = f"{os_text} ({result.os_accuracy}%)"
        self._table.setItem(row, OS_COLUMN_INDEX, self._make_item(os_text, Qt.AlignLeft))
        self._table.setItem(row, SCORE_COLUMN_INDEX, self._make_item(str(result.score), Qt.AlignRight))
        display_priority = self._priority_labels.get(result.priority, result.priority)
        priority_item = self._make_item(display_priority, Qt.AlignCenter)
        self._table.setItem(row, PRIORITY_COLUMN_INDEX, priority_item)
        error_text = "\n".join(format_error_list(result.errors, self._language))
        self._table.setItem(row, ERROR_COLUMN_INDEX, self._make_item(error_text, Qt.AlignLeft))
        diag_label = self._diagnostics_status_label(result.diagnostics_status)
        self._table.setItem(row, DIAGNOSTICS_COLUMN_INDEX, self._make_item(diag_label, Qt.AlignCenter))
        self._apply_row_style(row, result.priority)

    def _attach_row_checkboxes(self, row: int, target: str) -> None:
        advanced_cb = QCheckBox()
        advanced_cb.setChecked(target in self._advanced_selection)
        advanced_cb.stateChanged.connect(
            lambda state, t=target: self._on_row_checkbox_changed("advanced", t, state)
        )
        self._table.setCellWidget(row, ADVANCED_COLUMN_INDEX, self._wrap_checkbox_widget(advanced_cb))

        os_cb = QCheckBox()
        os_cb.setChecked(target in self._os_selection)
        os_cb.setEnabled(self._os_selection_allowed and target in self._advanced_selection)
        if not self._os_selection_allowed and self._os_tooltip:
            os_cb.setToolTip(self._os_tooltip)
        os_cb.stateChanged.connect(lambda state, t=target: self._on_row_checkbox_changed("os", t, state))
        self._table.setCellWidget(row, OS_OPTION_COLUMN_INDEX, self._wrap_checkbox_widget(os_cb))

        safety_cb = QCheckBox()
        safety_cb.setChecked(target in self._safety_selection)
        safety_cb.stateChanged.connect(
            lambda state, t=target: self._on_row_checkbox_changed("safety", t, state)
        )
        self._table.setCellWidget(row, SAFETY_COLUMN_INDEX, self._wrap_checkbox_widget(safety_cb))

        self._row_checkboxes[target] = {
            "advanced": advanced_cb,
            "os": os_cb,
            "safety": safety_cb,
        }

    def _wrap_checkbox_widget(self, checkbox: QCheckBox) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(checkbox, alignment=Qt.AlignCenter)
        return widget

    def _make_item(self, text: str, alignment: Qt.AlignmentFlag | None = None) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        if alignment is not None:
            item.setTextAlignment(int(alignment | Qt.AlignVCenter))
        return item

    def _on_row_checkbox_changed(self, kind: str, target: str, state: int) -> None:
        checked = Qt.CheckState(state) == Qt.CheckState.Checked
        if kind == "advanced":
            if checked:
                self._advanced_selection.add(target)
                checkbox = self._row_checkboxes.get(target, {}).get("os")
                if checkbox:
                    checkbox.setEnabled(self._os_selection_allowed)
            else:
                removed = target in self._advanced_selection
                self._advanced_selection.discard(target)
                if target in self._os_selection:
                    self._os_selection.discard(target)
                checkbox = self._row_checkboxes.get(target, {}).get("os")
                if checkbox:
                    checkbox.blockSignals(True)
                    checkbox.setChecked(False)
                    checkbox.setEnabled(False)
                    checkbox.blockSignals(False)
                if removed:
                    self.selectionChanged.emit()
                    self._sync_select_all_checkboxes()
                    return
        elif kind == "os":
            if target not in self._advanced_selection:
                checkbox = self._row_checkboxes.get(target, {}).get("os")
                if checkbox:
                    checkbox.blockSignals(True)
                    checkbox.setChecked(False)
                    checkbox.blockSignals(False)
                return
            if checked:
                self._os_selection.add(target)
            else:
                self._os_selection.discard(target)
        elif kind == "safety":
            if checked:
                self._safety_selection.add(target)
            else:
                self._safety_selection.discard(target)
        self._sync_select_all_checkboxes()
        self.selectionChanged.emit()

    def _sync_select_all_checkboxes(self) -> None:
        total_rows = len(self._row_checkboxes)
        self._set_select_all_state(self._advanced_select_all_checkbox, len(self._advanced_selection), total_rows)
        advanced_count = len(self._advanced_selection)
        self._set_select_all_state(
            self._os_select_all_checkbox,
            len(self._os_selection),
            advanced_count or total_rows,
        )
        self._set_select_all_state(self._safety_select_all_checkbox, len(self._safety_selection), total_rows)

    def _set_select_all_state(self, checkbox: QCheckBox, selected: int, total: int) -> None:
        checkbox.blockSignals(True)
        checkbox.setCheckState(Qt.Checked if total > 0 and selected == total else Qt.Unchecked)
        checkbox.blockSignals(False)

    def _rebuild_row_index_from_table(self) -> None:
        self._result_index.clear()
        for row in range(self._table.rowCount()):
            item = self._table.item(row, TARGET_COLUMN_INDEX)
            if item:
                self._result_index[item.text()] = row

    def _update_select_all_enabled(self) -> None:
        has_rows = bool(self._row_checkboxes)
        self._advanced_select_all_checkbox.setEnabled(has_rows)
        self._safety_select_all_checkbox.setEnabled(has_rows)
        self._update_os_select_all_enabled()

    def _update_os_select_all_enabled(self) -> None:
        has_rows = bool(self._row_checkboxes)
        self._os_select_all_checkbox.setEnabled(self._os_selection_allowed and has_rows)
        if not self._os_selection_allowed:
            self._os_select_all_checkbox.setCheckState(Qt.Unchecked)

    def _refresh_os_checkbox_states(self) -> None:
        allowed = self._os_selection_allowed
        for target, widgets in self._row_checkboxes.items():
            os_cb = widgets.get("os")
            if not os_cb:
                continue
            enable = allowed and (target in self._advanced_selection)
            os_cb.setEnabled(enable)
            if not enable and os_cb.isChecked():
                os_cb.blockSignals(True)
                os_cb.setChecked(False)
                os_cb.blockSignals(False)
                self._os_selection.discard(target)
            if not allowed and self._os_tooltip:
                os_cb.setToolTip(self._os_tooltip)
            elif os_cb.toolTip():
                os_cb.setToolTip("")
        self._sync_select_all_checkboxes()

    def _diagnostics_status_label(self, status: str) -> str:
        key_map = {
            "not_started": "diagnostics_status_not_started",
            "running": "diagnostics_status_running",
            "completed": "diagnostics_status_completed",
            "failed": "diagnostics_status_failed",
        }
        return self._t(key_map.get(status, "diagnostics_status_not_started"))

    def _apply_row_style(self, row: int, priority: str) -> None:
        color = self._priority_color(priority)
        if not color:
            return
        for col in range(self._table.columnCount()):
            item = self._table.item(row, col)
            if item:
                item.setBackground(color)

    def _priority_color(self, priority: str) -> QColor | None:
        color_hex = self._priority_color_overrides.get(priority)
        if color_hex:
            return QColor(color_hex)
        return DEFAULT_PRIORITY_COLORS.get(priority)

    def _handle_sort_request(self, column: int) -> None:
        if self._sort_column == column:
            self._sort_order = (
                Qt.DescendingOrder if self._sort_order == Qt.AscendingOrder else Qt.AscendingOrder
            )
        else:
            self._sort_column = column
            self._sort_order = Qt.AscendingOrder

        header = self._table.horizontalHeader()
        header.setSortIndicatorShown(True)
        header.setSortIndicator(column, self._sort_order)
        if not self._table.isSortingEnabled():
            self._table.setSortingEnabled(True)
        self._table.sortItems(column, self._sort_order)
        self._rebuild_row_index_from_table()
