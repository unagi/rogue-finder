# AGENTS BRIEFING

## Purpose & Scope
- Desktop utility built with PySide6 that orchestrates lightweight Nmap discovery jobs and ranks targets so analysts can decide where to spend commercial scanner time.
- Nmap is never bundled. The local `nmap` binary must exist on `PATH`; failures manifest as `NmapNotInstalledError` from `nmap_runner.ensure_nmap_available()`.
- The GUI is intended to stay portable (Windows/macOS/Linux) and drive PyInstaller packaging via `.github/workflows/pyinstaller.yml`.

## Runtime Architecture
- Entry point is `python -m nmap_gui.main` (or `src/nmap_gui/main.py`). It wires an `argparse --debug` flag, initializes `QApplication`, and shows `MainWindow`.
- `MainWindow` (`src/nmap_gui/gui.py`) owns the PySide6 widgets, collects targets/scopes, and emits `ScanConfig` objects.
- `ScanManager`/`ScanWorker` (`src/nmap_gui/scan_manager.py`) bridge the GUI thread to multiprocessing. Each scan runs in a `ProcessPoolExecutor` using the `spawn` context so Windows builds work. Cancellation toggles a shared event checked between phases.
- `run_full_scan` (`src/nmap_gui/nmap_runner.py`) executes up to three phases (ICMP `-sn -PE`, targeted TCP SYN `-sS` against `PORT_SCAN_LIST`, OS fingerprint `-O -Pn`). Each phase parses XML output to populate `HostScanResult` and then hands it to the rating engine.
- Export buttons call `exporters.export_csv/json` to produce UTF-8 CSV/JSON files. Score breakdowns get JSON-dumped so analysts can trace how a score was formed.

## Rating System Essentials
- Rules mirror `nmap_gui_system_spec.md`.
- `rating.apply_rating` assigns:
  - +2 if ICMP alive.
  - Port weights: 21/445/3389/5985 etc. mostly +2, DB & dev ports +1, see `PORT_WEIGHTS`.
  - High port bonus: +1 when 50000 is open.
  - OS weights (string-matched): Windows & SOHO/IoT +3, legacy Linux +2, generic Linux +1, Unknown +1.
  - Combo bonuses: {22 & (3306/5432)}, {3389 & 1433}, {8080 & 5672 & 15672}.
- Priority bands: `>=8 High`, `5-7 Medium`, `<5 Low`. The GUI colors rows per `PRIORITY_COLORS`.

## Developer Workflow
- Tooling is described in README:
  1. Install Python 3.11+ and `uv` (required because Poe tasks call `uv run`). Optional: `uv tool install poethepoet && uv tool update-shell` puts the `poe` shim on PATH even outside a venv.
  2. `uv venv && source .venv/bin/activate` (or preferred venv method).
  3. `uv pip install -r requirements-dev.txt` to get PySide6, pytest, pytest-spec, poethepoet, etc.
  4. Run the suite with `poe test` (this now shells out to `uv run pytest --spec`). Tests live under `tests/` and already cover `models.sanitize_targets` and rating heuristics.
- When packaging, rely on GitHub Actions PyInstaller workflow—every push to `main` builds Windows artifacts, tags trigger Windows + macOS outputs.

## Operational Notes
- Users must install Nmap separately (README lists OS-specific commands). If `run_full_scan` can’t find Nmap it records the error in `HostScanResult.errors` so the GUI can surface it.
- GUI target input accepts comma, newline, tab, semicolon separators—`sanitize_targets` normalizes these before deduplication.
- Multiprocessing spawn plus `freeze_support()` keeps the PyInstaller build stable on Windows.
- CSV/JSON exports include score breakdowns and error strings so analysts can audit decisions without rerunning scans.
- Keep dependencies minimal to maintain OSS friendliness; new libraries should be justified.

## How To Extend Safely
- Add new scan phases by extending `ScanMode`, making sure cancellation is respected between phases and rating inputs remain deterministic.
- Rating tweaks should update both `rating.py` and `nmap_gui_system_spec.md`, plus add/adjust pytest expectations so `poe test` guards regressions.
- Any UI addition should funnel through `MainWindow` and communicate with `ScanManager` via Qt signals to avoid blocking the GUI thread.
- Before shipping binaries, verify local scans with live or fixture XML to avoid flapping combo scores.
