# Nmap GUI Discovery & Rating Tool

Cross-platform PySide6 desktop application that orchestrates light-weight Nmap discovery jobs and ranks hosts based on custom heuristics defined in `nmap_gui_system_spec.md`. The GUI runs locally on Windows and macOS (and Linux) without bundling Nmap itself.

## Features
- ICMP, targeted TCP port, and OS fingerprint phases executed through the local `nmap` binary
- Concurrent scanning via `ProcessPoolExecutor` with cancel support
- Automatic rating engine aligned with the provided scoring tables
- Rich table view with inline priority colors plus CSV / JSON export buttons

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

## Internals
- `src/nmap_gui/gui.py`: PySide6 widgets and UX wiring
- `src/nmap_gui/scan_manager.py`: bridges GUI signals to multiprocessing workers
- `src/nmap_gui/nmap_runner.py`: subprocess wrapper plus XML parsers
- `src/nmap_gui/rating.py`: implements the scoring logic from the spec
- `src/nmap_gui/exporters.py`: CSV / JSON helpers

The project intentionally keeps dependencies minimal to stay OSS-friendly and portable.

## Development
The project recommends the [uv](https://docs.astral.sh/uv/) toolchain for fast, reproducible environments.

1. Install uv (see official docs for platform instructions)
2. Create and activate a virtual environment:
   ```bash
   uv venv
   source .venv/bin/activate      # Windows: .venv\Scripts\activate
   ```
3. Install dev dependencies (includes pytest-spec and poethepoet):
   ```bash
   uv pip install -r requirements-dev.txt
   ```
4. Run the pytest-spec suite via Poe:
   ```bash
   poe test
   ```
   (Under the hood this executes `pytest --spec` per `pyproject.toml`.)

## Continuous Integration
- GitHub Actions now bundles the app with PyInstaller.
- Every push to `main` builds the Windows binary so merge commits stay green.
- Pushing a Git tag (for example `v1.0.0`) triggers both Windows and macOS builds. Each job uploads its PyInstaller output as an artifact you can attach to a GitHub Release.

## Platform Notes
- **Windows:** First launch of the unsigned binary may trigger SmartScreen. Click **More info** → **Run anyway** if you trust the build.
- **macOS:** Gatekeeper tags downloaded binaries with the `com.apple.quarantine` attribute. Run `xattr -dr com.apple.quarantine /path/to/rogue-finder` (adjusting the path to where you saved the app) before double-clicking the executable, otherwise macOS will refuse to open it.
