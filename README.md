# Nmap GUI Discovery & Rating Tool

Cross-platform PySide6 desktop application that orchestrates light-weight Nmap discovery jobs and ranks hosts based on custom heuristics defined in `nmap_gui_system_spec.md`. The GUI runs on Windows, macOS, and Linux without bundling Nmap itself, but Windows currently offers the most complete feature set (see **Platform Recommendations** below).

## Features
- ICMP, targeted TCP port, and OS fingerprint phases executed through the local `nmap` binary
- Concurrent scanning via `ProcessPoolExecutor` with cancel support
- Automatic rating engine aligned with the provided scoring tables
- Rich table view with inline priority colors plus CSV / JSON export buttons
- One-click per-target `nmap --script safe` diagnostics with bounded concurrency (default 2) and text report export
- Detailed mapping between GUI actions and the exact `nmap` commands they invoke lives in [docs/scan_execution.md](docs/scan_execution.md).

## Prerequisites
1. Python 3.11+
2. `pip install -r requirements.txt`
3. Install Nmap separately and ensure the `nmap` binary is on your `PATH`:
   - **Windows**: install from <https://nmap.org/download.html>, then restart the terminal so `nmap.exe` is visible
   - **macOS**: `brew install nmap` (or install the dmg from nmap.org). GUI builds run without elevated privileges, so ICMP/SYN/OS phases fall back to TCP connect-only mode unless you explicitly run the CLI with `sudo`.

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

## Configuration
Rogue Finder automatically ensures a `rogue-finder.config.yaml` file exists in the directory you launch the app from (next to the PyInstaller binary or your working tree). If the file is missing it is created with defaults; when the schema grows in future releases, missing keys are added automatically while your existing overrides stay intact.

Key sections you can tune:

- `scan`: timeout per phase (`default_timeout_seconds`), port list (`port_scan_list`), and the high-port cutoff considered interesting.
- `rating`: ICMP/port/OS weights plus combo bonuses and priority thresholds.
- `ui`: priority row colors (hex strings).
- `safe_scan`: simulated progress timings for the safe-script dialog.

Because the file is human-friendly YAML, you can version-control it per environment or ship different defaults for specific teams. Use the helper command below to dump the latest template without launching the GUI:

```bash
python -m nmap_gui.config --write-default ./rogue-finder.config.yaml
```

### Safe Script Diagnostics

- The diagnostics button appears next to every discovered target once the discovery scan returns results.
- Safe-script runs observe the `safe_scan.max_parallel` limit (default 2) so you can process a small batch concurrently without overwhelming the host; discovery scans must be idle before launching diagnostics.
- While the diagnostic is active the primary Start/Stop controls and all Safe Script buttons are disabled; the status bar shows which target is currently being evaluated.
- When the run finishes a modal dialog summarizes the execution context, stdout/stderr, and any structured errors. Use **Save Report** to persist the textual transcript; filenames default to `safe-scan_<target>_<timestamp>.txt` to avoid accidental overwrites.
- A dedicated progress bar simulates movement based on a 10-minute baseline (matching `safe_scan.default_duration_seconds`) and automatically stretches if the session's average runtime exceeds that baseline, so "stuck" scans still show forward progress.
- The ETA shown for both advanced discovery and Safe Script now factors in (a) how many hosts are queued, (b) each phase's worker parallelism, and (c) the per-host timeout. The first batch assumes the full timeout to avoid over-promising, then shortens future estimates using the observed runtimes recorded in the session history.

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
   - If you want the `poe` command available globally, run `uv tool install poethepoet` followed by `uv tool update-shell` so it is added to your PATH.
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

### Optional CLI helpers for AI/Desktop automation
If you frequently drive AI agents or non-interactive shells, installing a few lightweight CLI tools can drastically cut down on `curl` + `grep` loops:

- `lynx` or `w3m` – dump HTML pages as plain text so you can `rg` through documentation without a browser.
- `htmlq` or `pup` – CSS-selector extractors; perfect for grabbing specific DOM nodes from fetched HTML.
- `jq` – indispensable for slicing JSON APIs or GitHub responses.
- `ddgr` (DuckDuckGo CLI) – run web searches directly from the terminal and open results without context switching.
- `gh` – GitHub’s official CLI for searching issues/PRs and opening them in the browser with one command.

Keeping these in your toolbox makes “ask the web → gather context → continue coding” loops much faster when working purely from the terminal.

## Continuous Integration
- GitHub Actions now bundles the app with PyInstaller.
- Every push to `main` builds the Windows binary so merge commits stay green.
- Pushing a Git tag (for example `v1.0.0`) triggers both Windows and macOS builds. Each job uploads its PyInstaller output as an artifact you can attach to a GitHub Release.
- Tag pushes also trigger the **Release Changelog** workflow, which regenerates `CHANGELOG.md` with git-cliff and opens an automated PR.

## Release & Changelog Workflow
1. Make sure `main` is green and create an annotated tag such as `git tag -a 0.2.0 -m "Release 0.2.0"`.
2. `git push origin 0.2.0` (or `v0.2.0`) to kick off the packaging and changelog workflows.
3. Wait for the **Release Changelog** workflow to finish. It runs `git-cliff` with `cliff.toml`, updates `CHANGELOG.md`, and opens a PR named `docs: update changelog for <tag>`.
4. Review the autogenerated PR (diff should only touch `CHANGELOG.md`) and merge it once satisfied. The merged PR ensures `main` always has a fresh changelog entry for the released tag.

## Platform Recommendations

- **Windows (recommended):** Full ICMP/SYN/OS coverage and PyInstaller builds that can run every phase without additional setup.
- **macOS:** Launching the GUI via Finder/Dock runs as a normal user, so raw socket features are not available. The app automatically downgrades to TCP ping and TCP connect scans and skips OS fingerprinting. Run `sudo python -m nmap_gui.main --debug` (or `sudo /Applications/RogueFinder.app/Contents/MacOS/RogueFinder`) if you need full fidelity, or consider scanning from Windows for the best experience.
- **Linux:** Behaves like Windows when executed with sufficient privileges; otherwise it inherits the same TCP-only limitations.

## Platform Notes
- **Windows:** First launch of the unsigned binary may trigger SmartScreen. Click **More info** → **Run anyway** if you trust the build.
- **macOS:** Release binaries target Apple Silicon (arm64). Intel Macs should run the app from source (`python -m nmap_gui.main`). Gatekeeper tags downloaded binaries with the `com.apple.quarantine` attribute; run `xattr -dr com.apple.quarantine /path/to/rogue-finder` before first launch. When running the GUI without `sudo`, ICMP (`-sn -PE`), SYN (`-sS`), and OS (`-O`) phases degrade to TCP ping/connect scans and OS detection is skipped entirely.
- **macOS / Linux:** The OS fingerprint phase (`-O`) requires root privileges. Restart the app from Terminal with `sudo python3 -m nmap_gui.main --debug` (or `sudo /path/to/rogue-finder` for the packaged binary) when you need OS detection, or rely on the TCP-only fallback that the GUI now applies automatically when it detects insufficient privileges.
