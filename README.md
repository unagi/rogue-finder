# Nmap GUI Discovery & Rating Tool

Cross-platform PySide6 desktop application that orchestrates light-weight Nmap discovery jobs and ranks hosts based on custom heuristics defined in `nmap_gui_system_spec.md`. The GUI runs locally on Windows and macOS (and Linux) without bundling Nmap itself.

## Features
- ICMP, targeted TCP port, and OS fingerprint phases executed through the local `nmap` binary
- Concurrent scanning via `ProcessPoolExecutor` with cancel support
- Automatic rating engine aligned with the provided scoring tables
- Rich table view with inline priority colors plus CSV / JSON export buttons
- One-click per-target `nmap --script safe` diagnostics with serialized execution and text report export

## Prerequisites
1. Python 3.11+
2. `pip install -r requirements.txt`
3. Install Nmap separately and ensure the `nmap` binary is on your `PATH`:
   - **Windows**: install from <https://nmap.org/download.html>, then restart the terminal so `nmap.exe` is visible
   - **macOS**: `brew install nmap` (or install the dmg from nmap.org)

## Run
```bash
python -m nmap_gui.main
```
Add `--debug` for verbose logging.

## Usage
1. Enter single IPs, ranges, or CIDR blocks (one per line or comma-separated)
2. Select scan phases (all enabled by default)
3. Click **Start** to launch concurrent scans, **Stop** to cancel
4. Review results in the table – rows are tinted by priority (High / Medium / Low)
5. Export via CSV or JSON once results are available
6. Use the new **Safe Script** action on any discovered host to launch a serialized `nmap --script safe` run; results open in a dedicated dialog where you can review the command/output and save a timestamped text report

### Safe Script Diagnostics

- The diagnostics button appears next to every discovered target once the discovery scan returns results.
- Only one safe-script run can execute at a time, and discovery scans must be idle before launching diagnostics to keep total Nmap load predictable.
- While the diagnostic is active the primary Start/Stop controls and all Safe Script buttons are disabled; the status bar shows which target is currently being evaluated.
- When the run finishes a modal dialog summarizes the execution context, stdout/stderr, and any structured errors. Use **Save Report** to persist the textual transcript; filenames default to `safe-scan_<target>_<timestamp>.txt` to avoid accidental overwrites.
- A dedicated progress bar simulates movement based on a 2-minute baseline (matching `-T4`) and automatically stretches if the current session's average runtime exceeds that baseline, so "stuck" scans still show forward progress.

## Internals
- `src/nmap_gui/gui.py`: PySide6 widgets and UX wiring
- `src/nmap_gui/scan_manager.py`: bridges GUI signals to multiprocessing workers
- `src/nmap_gui/nmap_runner.py`: subprocess wrapper plus XML parsers
- `src/nmap_gui/rating.py`: implements the scoring logic from the spec
- `src/nmap_gui/exporters.py`: CSV / JSON helpers

The project intentionally keeps dependencies minimal to stay OSS-friendly and portable.

## Development
The project standardizes on the [uv](https://docs.astral.sh/uv/) toolchain for fast, reproducible environments (Poe tasks call `uv run` internally).

1. Install uv (see official docs for platform instructions)
   - もしグローバルに `poe` コマンドを使いたい場合は `uv tool install poethepoet` の後に `uv tool update-shell` を実行すると PATH に追加できます。
2. Create and activate a virtual environment:
   ```bash
   uv venv
   source .venv/bin/activate      # Windows: .venv\Scripts\activate
   ```
3. Install dev dependencies (includes pytest-spec and poethepoet):
   ```bash
   uv pip install -r requirements-dev.txt
   ```
4. Run the pytest-spec suite via Poe (automatically executes `uv run pytest --spec`):
  ```bash
  poe test
  ```
  (Poe shells out to `uv run pytest --spec` per `pyproject.toml`.)

## Continuous Integration
- GitHub Actions now bundles the app with PyInstaller.
- Every push to `main` builds the Windows binary so merge commits stay green.
- Pushing a Git tag (for example `v1.0.0`) triggers both Windows and macOS builds. Each job uploads its PyInstaller output as an artifact you can attach to a GitHub Release.

## Platform Notes
- **Windows:** First launch of the unsigned binary may trigger SmartScreen. Click **More info** → **Run anyway** if you trust the build.
- **macOS:** Release binaries target Apple Silicon (arm64). Intel Macs should run the app from source (`python -m nmap_gui.main`). Gatekeeper tags downloaded binaries with the `com.apple.quarantine` attribute; run `xattr -dr com.apple.quarantine /path/to/rogue-finder` before first launch.
- **macOS / Linux:** The OS fingerprint phase (`-O`) requires root privileges. Restart the app from Terminal with `sudo python3 -m nmap_gui.main --debug` (or `sudo /path/to/rogue-finder` for the packaged binary) when you need OS detection, or uncheck the OS mode to scan without it.
