# AGENTS BRIEFING

## Purpose & Scope
- Desktop utility built with PySide6 that orchestrates lightweight Nmap discovery jobs and ranks targets so analysts can decide where to spend commercial scanner time.
- Nmap is never bundled. The local `nmap` binary must exist on `PATH`; failures manifest as `NmapNotInstalledError` from `nmap_runner.ensure_nmap_available()`.
- The GUI is intended to stay portable (Windows/macOS/Linux) and drive PyInstaller packaging via `.github/workflows/release.yml`.

## Runtime Architecture
- Entry point is `python -m nmap_gui.main` (or `src/nmap_gui/main.py`). It wires an `argparse --debug` flag, initializes `QApplication`, and shows `MainWindow`.
- PyInstaller executes `main.py` as a top-level script, so keep absolute-import fallbacks (`from nmap_gui...`) next to the usual relative imports for `gui`, `config`, etc., or the packaged EXE will crash with “attempted relative import with no known parent package.”
- `MainWindow` (`src/nmap_gui/gui.py`) owns the PySide6 widgets, collects targets/scopes, and emits `ScanConfig` objects.
- `ScanManager`/`ScanWorker` (`src/nmap_gui/scan_manager.py`) bridge the GUI thread to multiprocessing. Each scan runs in a `ProcessPoolExecutor` using the `spawn` context so Windows builds work. Cancellation toggles a shared event checked between phases.
- `run_full_scan` (`src/nmap_gui/nmap_runner.py`) executes up to three phases (ICMP `-sn -PE`, targeted TCP SYN `-sS` against `PORT_SCAN_LIST`, OS fingerprint `-O -Pn`). On macOS without root privileges the runner automatically downgrades to TCP ping (`-PA`) and TCP connect (`-sT`) scans and skips OS fingerprinting to avoid raw-socket failures. Each phase parses XML output to populate `HostScanResult` and then hands it to the rating engine.
- See `docs/scan_execution.md` for a mode-by-mode breakdown of how GUI actions map to concrete `nmap` commands (fast, advanced, and safe-script diagnostics).
- Export buttons call `exporters.export_csv/json` to produce UTF-8 CSV/JSON files. Score breakdowns get JSON-dumped so analysts can trace how a score was formed.

## Rating System Essentials
- Rules mirror the inline summary in README (“Rating Model Overview”) and the constants defined in `rating.py`.
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
  4. Run the suite with `poe test` (wraps `coverage run -m pytest --spec`, producing XML + HTML reports). Tests live under `tests/` and already cover `models.sanitize_targets` and rating heuristics.
  5. Run `poe lint` (backs `ruff check src tests`) before committing to keep packaging imports and style consistent.
- Pull requests automatically run `poe lint` and `poe test` via `.github/workflows/ci.yml`. Keep those tasks green before requesting review.
- Treat line coverage below 80% as a release blocker; when `poe test` reports less than that threshold, add or expand tests before merging so CI stays consistently green.
- When packaging, rely on `.github/workflows/release.yml` (“Release Builds”)—pushes to `main` keep Windows artifacts fresh, and annotated tags trigger both Windows + macOS builds, release uploads, coverage-to-Pages, and the automated changelog PR step.
- The changelog automation requires a `CHANGELOG_TOKEN` repository secret (a fine-scoped PAT with `contents:write` and `pull_requests:write`). If the secret is missing the job is skipped; set it before tagging so the PR step succeeds.
- When editing any GitHub Actions workflow, pin every `uses:` reference to a full-length commit SHA. Pick the desired release tag (usually “latest patch within the in-use major”) with `gh release list --repo OWNER/REPO`, then resolve its commit via `gh api repos/OWNER/REPO/git/refs/tags/<tag>` (or `/heads/<branch>` when an action only ships branches). Paste the SHA plus a trailing comment like `# actions/checkout@v4.3.1` so future upgrades know which tag was locked.
- Avoid hand-editing the changelog; regenerate locally via `git cliff -c cliff.toml -o CHANGELOG.md` if you need to preview.

## Development Mindset
- Always validate external resources and migration guidance with Context7 first; only fall back to broader research if Context7 cannot resolve the issue.
- Dockerfile problems usually surface during `docker build`, so run local builds whenever possible to reproduce and fix failures before pushing changes.

## Operational Notes
- Users must install Nmap separately (README lists OS-specific commands). If `run_full_scan` can’t find Nmap it records the error in `HostScanResult.errors` so the GUI can surface it.
- GUI target input accepts comma, newline, tab, semicolon separators—`sanitize_targets` normalizes these before deduplication.
- Multiprocessing spawn plus `freeze_support()` keeps the PyInstaller build stable on Windows.
- macOS builds run as regular users (no code signing / helper), so ICMP/SYN/OS phases fall back to TCP-only behavior; warn users in the GUI and README to prefer Windows for full coverage or run the CLI with `sudo` when necessary.
- CSV/JSON exports include score breakdowns and error strings so analysts can audit decisions without rerunning scans.
- Keep dependencies minimal to maintain OSS friendliness; new libraries should be justified.
- ETA values for advanced discovery and Safe Script are calculated from the target count, worker parallelism, and each phase’s timeout. The first batch assumes the full timeout, then subsequent batches shorten the estimate using the runtime history captured during the session.
- When documenting example targets (README, docs, translations, tests), stick to the RFC 5737 documentation blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) instead of private LAN ranges; this keeps Sonar Security Hotspots satisfied while still conveying realistic inputs.
- Keep `docs/rogue_finder_manual_en.md` and `docs/rogue_finder_manual_ja.md` in lockstep—whenever one changes structure or content, update the other so translators and operators can rely on identical guidance in both languages.

## How To Extend Safely
- Add new scan phases by extending `ScanMode`, making sure cancellation is respected between phases and rating inputs remain deterministic.
- Rating tweaks should update `rating.py` (plus README’s “Rating Model Overview”) and add/adjust pytest expectations so `poe test` guards regressions.
- Any UI addition should funnel through `MainWindow` and communicate with `ScanManager` via Qt signals to avoid blocking the GUI thread.
- Before shipping binaries, verify local scans with live or fixture XML to avoid flapping combo scores.
