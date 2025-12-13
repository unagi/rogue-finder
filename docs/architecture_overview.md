# Architecture Overview

This document summarizes the moving pieces inside Rogue Finder so contributors can quickly map GUI controls to multiprocessing workers, scan runners, and scoring/export utilities. For exact `nmap` arguments see `docs/scan_execution.md`.

## Runtime Flow

1. **Entry point** – `python -m nmap_gui.main` (or `src/nmap_gui/main.py`) builds an `argparse` interface (`--debug` flag), instantiates `QApplication`, and shows `MainWindow`.
2. **Main window** – `src/nmap_gui/gui/main_window.py` wires top-level widgets (target input, scan controls, results grid, safe diagnostics). It emits `ScanConfig` objects via Qt signals whenever the user starts discovery or diagnostics jobs.
3. **Scan bridge** – `src/nmap_gui/scan_manager.py` listens to GUI events, translates them into background work items, and fan-outs execution to a `ProcessPoolExecutor` created with the `spawn` context (so Windows builds stay stable). Cancellation toggles a shared `multiprocessing.Event` from `cancel_token.py`.
4. **Worker phase** – Each process executes `nmap_runner.run_full_scan`, which orchestrates ICMP discovery, targeted TCP SYN/TCP connect scans, optional OS fingerprinting, and safe-script jobs. XML outputs are parsed into `models.HostScanResult` objects, rated, and streamed back to the GUI thread.
5. **Result presentation** – `result_grid.py` plus the supporting widgets in `src/nmap_gui/gui/` render the table, score breakdown, actions, and safe diagnostics dialogs. Export buttons call `exporters.export_csv/json`.

## GUI Layer

| Module | Responsibility |
| --- | --- |
| `gui/main_window.py` | Creates the primary window, menus, and status bar. |
| `gui/scan_controls.py` | Input widgets, scan mode toggles, and Start/Stop buttons. |
| `gui/summary_panel.py` & `result_grid.py` | Display scan progress, scores, and actionable rows. |
| `gui/safe_scan_controller.py`, `safe_scan_dialog.py`, `safe_scan_report_viewer.py` | Manage Safe Script diagnostics, concurrency limits, report display, and export. |
| `gui/config_editor.py` | Optional YAML editor launched from the GUI to tweak `rogue-finder.config.yaml`. |
| `gui/state_controller.py` & `state_store.py` | Persist UI state (window size, column order, etc.) between sessions. |

All widgets communicate via Qt signals/slots so the GUI thread stays responsive while background scans run.

## Background Services

- **Scan scheduling:** `scan_manager.py` batches targets based on selected phases, enforces per-mode worker limits, calculates ETAs via `job_eta.py`, and feeds workers in a backpressure-aware loop.
- **Nmap integration:** `nmap_runner.py` composes the correct command line per platform/privilege level. On macOS (non-root) it automatically downgrades to TCP ping (`-PA`) and TCP connect (`-sT`) scans and skips OS fingerprinting to avoid raw-socket errors. Errors are encoded as `HostScanResult.errors`.
- **Rating engine:** `rating.py` houses `PORT_WEIGHTS`, combo bonuses, OS heuristics, and priority bands. It returns both the numeric score and the structured `ScoreBreakdown` used for table tooltips and exports.
- **Safe diagnostics:** When a user runs Safe Script from the GUI, `safe_scan_controller.py` enqueues jobs capped by `safe_scan.max_parallel`. Each job calls the dedicated mode inside `nmap_runner.py` to launch `nmap --script safe`, gather stdout/stderr, and persist the transcript.

## Configuration & Persistence

- `config.py` loads/creates `rogue-finder.config.yaml`, merges user overrides with defaults, and exposes helpers to dump an up-to-date template (`python -m nmap_gui.config --write-default`).
- `storage_warnings.py` surfaces helpful alerts when the app lacks write permissions for config/export paths.
- `i18n.py` holds localized strings used in GUI labels and dialogs (English + Japanese coverage for the manuals).

## Packaging Considerations

- PyInstaller executes `main.py` as a script, so modules expose both relative (`from . import ...`) and absolute (`from nmap_gui import ...`) imports to avoid “attempted relative import with no known parent package” errors.
- Multiprocessing uses `spawn` everywhere to align with Windows and macOS requirements. Remember to guard entry points with `if __name__ == "__main__": multiprocessing.freeze_support()`.
- Release artifacts include the English/Japanese manuals (copied in `.github/workflows/pyinstaller.yml`) so operators always have the latest usage notes.

## Where to Start

- **Need to adjust scan behavior?** Touch `ScanMode` enums plus `scan_manager.py` scheduling and ensure `docs/scan_execution.md` stays accurate.
- **Tweaking scoring?** Update `rating.py`, README’s **Rating Model Overview**, and the pytest fixtures under `tests/` so CI catches regressions.
- **UI enhancements?** Implement them in `gui/` and communicate with `ScanManager` strictly via signals to keep the GUI thread non-blocking.

For deeper operational procedures (CI, releases, manuals) see README and the other documents referenced in the Quick Links section.
