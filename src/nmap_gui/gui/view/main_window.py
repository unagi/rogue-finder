"""PySide6 GUI for the Nmap discovery & rating application."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QWidget

from ...i18n import detect_language, translate
from ...job_eta import JobEtaController
from ..controller.main_window_controller import MainWindowController, MainWindowDependencies
from .export_toolbar import ExportToolbar
from .result_grid import ResultGrid
from .safe_scan_report_viewer import SafeScanReportViewer
from .scan_controls import ScanControlsPanel
from .summary_panel import SummaryPanel

if TYPE_CHECKING:
    from ...infrastructure.config import AppSettings
    from ...infrastructure.state import AppState
else:  # pragma: no cover - runtime placeholders for type checking only
    AppSettings = object  # type: ignore[assignment]
    AppState = object  # type: ignore[assignment]

DEFAULT_WINDOW_WIDTH = 1000
DEFAULT_WINDOW_HEIGHT = 700


# NOTE: MainWindow is instantiated directly from main.py. Keeping main.py thin and
# starting the window early (even in PyInstaller builds) requires injecting settings/state
# here and forwarding them to the controller.
class MainWindow(QMainWindow):
    """Primary top-level window."""

    def __init__(
        self,
        settings: AppSettings,
        state: AppState | None = None,
        app_icon: QIcon | None = None,
    ) -> None:
        super().__init__()
        self._settings = settings
        self._controller: MainWindowController | None = None
        self._configure_window_chrome(app_icon)
        self._controls = ScanControlsPanel(self._t, self)
        self._result_grid = ResultGrid(
            translator=self._t,
            language=self._language,
            priority_labels=self._priority_labels,
            priority_colors=self._settings.ui.priority_colors,
            parent=self,
        )
        self._summary_panel = SummaryPanel(self._t, self)
        self._export_toolbar = ExportToolbar(self._t, self)
        self._report_viewer = SafeScanReportViewer(self._t, self._language, self)
        self._initialize_summary_panel()
        self._build_ui()
        self._job_eta = self._create_job_eta()
        deps = MainWindowDependencies(
            window=self,
            settings=self._settings,
            translator=self._t,
            language=self._language,
            controls=self._controls,
            result_grid=self._result_grid,
            summary_panel=self._summary_panel,
            export_toolbar=self._export_toolbar,
            report_viewer=self._report_viewer,
            job_eta=self._job_eta,
        )
        self._controller = MainWindowController(deps)
        if not self._controller.initialize(state):
            QTimer.singleShot(0, self.close)

    def _configure_window_chrome(self, app_icon: QIcon | None) -> None:
        self._language = detect_language()
        self._priority_labels = {
            "High": translate("priority_high", self._language),
            "Medium": translate("priority_medium", self._language),
            "Low": translate("priority_low", self._language),
        }
        self.setWindowTitle(self._t("window_title"))
        if app_icon is not None and not app_icon.isNull():
            self.setWindowIcon(app_icon)

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self._controls)
        layout.addWidget(self._result_grid.widget())
        layout.addWidget(self._summary_panel)
        layout.addWidget(self._export_toolbar)
        layout.setStretch(0, 0)
        layout.setStretch(1, 2)
        layout.setStretch(2, 0)
        layout.setStretch(3, 0)
        self.setCentralWidget(central)
        self._apply_initial_window_size()
        self.statusBar().showMessage(self._t("ready"))

    def _apply_initial_window_size(self) -> None:
        self.resize(DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT)

    def _initialize_summary_panel(self) -> None:
        self._summary_panel.update_summary(
            target_count=0,
            requested_hosts=0,
            discovered_hosts=0,
            alive_hosts=0,
            status=self._t("summary_status_idle"),
        )

    def _create_job_eta(self) -> JobEtaController:
        return JobEtaController(
            self,
            self.statusBar().showMessage,
            summary_callback=None,
        )

    def _t(self, key: str) -> str:
        return translate(key, self._language)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._controller and not self._controller.handle_close_event():
            event.ignore()
            return
        super().closeEvent(event)
