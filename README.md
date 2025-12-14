# Nmap GUI Discovery & Rating Tool

[![CI](https://github.com/unagi/rogue-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/unagi/rogue-finder/actions/workflows/ci.yml)
[![Release Builds](https://github.com/unagi/rogue-finder/actions/workflows/release.yml/badge.svg)](https://github.com/unagi/rogue-finder/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/unagi/rogue-finder?sort=semver)](https://github.com/unagi/rogue-finder/releases)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=unagi_rogue-finder&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=unagi_rogue-finder)

PySide6 desktop application that orchestrates lightweight Nmap discovery jobs, ranks hosts via a transparent heuristic model, and exports audit-friendly evidence so analysts can focus commercial scanners where it matters most.

**Highlights**
- ICMP, targeted port, OS, and safe-script phases launched through the local `nmap` binary (never bundled).
- Cross-platform (Windows/macOS/Linux) with PyInstaller packaging artifacts published by GitHub Actions.
- Optional Windows-only privileged runner keeps the GUI unelevated while a spawned helper receives the single UAC prompt and runs all Nmap phases via named-pipe IPC.
- Deterministic scoring engine with CSV/JSON exports containing score breakdowns and error context.

## Quick Links
- User Manual (English): [`docs/rogue_finder_manual_en.md`](docs/rogue_finder_manual_en.md)
- ユーザーマニュアル (日本語): [`docs/rogue_finder_manual_ja.md`](docs/rogue_finder_manual_ja.md)
- Scan execution reference: [`docs/scan_execution.md`](docs/scan_execution.md)
- Architecture overview: [`docs/architecture_overview.md`](docs/architecture_overview.md)
- Agent/developer briefing: [`AGENTS.md`](AGENTS.md)
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)

## Quick Start (Developers)
1. **Install prerequisites**
   - Python 3.11+
   - [uv](https://docs.astral.sh/uv/) (required because Poe tasks shell out via `uv run`)
   - Locally installed Nmap (`nmap` must be on `PATH`).
2. **Bootstrap the repo**
   ```bash
   uv venv
   source .venv/bin/activate    # Windows: .venv\Scripts\activate
   uv pip install -r requirements-dev.txt
   ```
3. **Run lint/tests**
   ```bash
   poe lint
   poe test
   ```
   `poe test` now runs via `coverage`, leaving `coverage.xml` and an `htmlcov/` folder for SonarQube/GitHub Pages (both ignored by git).
4. **Launch the GUI**
   ```bash
   python -m nmap_gui.main --debug
   ```

### User Workflow (at a glance)
1. Paste IPs/CIDRs/hostnames (comma/newline/tab separators are OK).
2. Leave ICMP/Ports/OS phases enabled or toggle as needed.
3. Click **Start** to queue discovery jobs; **Stop** cancels in-flight work.
4. Review prioritized results (High/Medium/Low) and export CSV/JSON or run Safe Script diagnostics.
5. For full instructions and FAQs, see the English/Japanese user manuals.

## Windows Privileged Runner
- Windows builds now ship a dual-mode executable: the default GUI (`--mode gui`) stays in the user session while a helper launched with `--mode runner` receives the single UAC prompt and executes all Nmap phases. Both entry points live inside the same PyInstaller binary so distribution remains one file.
- The GUI and runner communicate exclusively through authenticated Windows named pipes; logs, progress, and results stream over that channel, keeping cancellation just as responsive as the legacy design.
- The helper remains alive for the duration of the GUI session, so the UAC consent dialog only appears the first time a scan kicks off (or if you stop and restart the helper manually). Closing the GUI tears down the privileged child automatically.
- Control the behavior via `rogue-finder.config.yaml` → `runtime.windows_privileged_runner` (default `true`). Set it to `false` if corporate policy forbids elevation prompts or when you prefer the historical single-process flow (macOS/Linux always run in that mode regardless of the flag).
- Power users rarely need to invoke `--mode runner` directly; the GUI passes `--ipc-name` and `--ipc-token` automatically when launching the helper. The flag is documented here for completeness and for future automation hooks.

## Rating Model Overview
The rules that previously lived in `nmap_gui_system_spec.md` are summarized here for convenience:

- **Alive detection:** +2 when ICMP (or the TCP fallback) proves that the host responded.
- **Port weights:** `PORT_WEIGHTS` emphasizes remote-admin ports such as 21/445/3389/5985 (typically +2 each) while database/dev/service ports like 3306/5432/8080/5672/15672 contribute +1. Update the dictionary inside `rating.py` when adding new ports.
- **High-port bonus:** +1 when TCP 50000 is open, signalling ad-hoc services.
- **OS strings:** Windows and SOHO/IoT fingerprints score +3, legacy Linux targets +2, generic Linux +1, and unknowns still receive +1 so they remain sortable.
- **Combo bonuses:** +1 for ssh+db pairs ({22 & (3306 or 5432)}), +1 for 3389 & 1433 together, and +2 when 8080, 5672, and 15672 all respond.
- **Priority bands:** Scores `>=8` are **High**, `5-7` are **Medium**, and `<5` are **Low**; the GUI maps these to `PRIORITY_COLORS` for row tinting.

Tuning `rogue-finder.config.yaml` → `rating` changes these weights at runtime, and `rating.apply_rating` is covered by `poe test`.

## Configuration Snapshot
Rogue Finder ensures `rogue-finder.config.yaml` exists in the directory you launch from. If absent, defaults are generated and future schema updates backfill missing keys without touching overrides.

Key sections:
- `scan` – per-phase timeouts (`default_timeout_seconds`, `advanced_timeout_seconds`), fast/full port lists, high-port cutoff, worker parallelism.
- `rating` – ICMP/port/OS weights plus combo bonuses and priority thresholds.
- `ui` – priority row colors.
- `safe_scan` – Safe Script concurrency, timeout, and ETA smoothing knobs.
- `runtime` – Windows-specific toggles such as `windows_privileged_runner` (default `true`).

Generate a fresh template anytime:
```bash
python -m nmap_gui.infrastructure.config --write-default ./rogue-finder.config.yaml
```

## Architecture Snapshot
For the full component map see [`docs/architecture_overview.md`](docs/architecture_overview.md). At a high level:

- `src/nmap_gui/main.py` boots `QApplication`, parses CLI flags, and shows `MainWindow`.
- Widgets under `src/nmap_gui/gui/` collect targets, display results, and emit `ScanConfig` objects without blocking the GUI thread.
- `src/nmap_gui/scan_manager.py` coordinates work through `ScanJobExecutor`, which falls back to threads on macOS/Windows for stability. When `runtime.windows_privileged_runner` is enabled, a named-pipe connected helper process runs Nmap with UAC elevation while the GUI stays unelevated.
- `src/nmap_gui/nmap_runner.py` executes ICMP/port/OS/safe-script phases, adapts to privilege limitations, and parses XML into `models.HostScanResult`.
- `rating.py`, `exporters.py`, and `job_eta.py` provide scoring, CSV/JSON output, and ETA calculations consumed by the GUI and tests.

## Documentation Hub
- Discovery/diagnostics command matrix: [`docs/scan_execution.md`](docs/scan_execution.md)
- Architecture deep dive: [`docs/architecture_overview.md`](docs/architecture_overview.md)
- User manuals (EN/JA): see [Quick Links](#quick-links)
- Agent/developer process notes: [`AGENTS.md`](AGENTS.md)
- Release notes & automation details: [`CHANGELOG.md`](CHANGELOG.md) and [Release workflow](https://github.com/unagi/rogue-finder/actions/workflows/release.yml)

## Development Guide
The repo standardizes on uv + Poe for reproducible environments.

- **Environment setup:** `uv venv && source .venv/bin/activate`, then `uv pip install -r requirements-dev.txt`.
- **Tooling:** `poe lint` (backs `ruff check src tests`), `poe test` (runs `coverage run -m pytest --spec` + emits XML/HTML coverage reports).
- **Optional helpers:** `uv tool install poethepoet && uv tool update-shell` to expose the `poe` shim globally.
- **Safe-script fixtures & XML parsing tests** already live in `tests/`; add coverage whenever rating or scan behavior changes.

### CI & Release Automation
- **CI workflow (`ci.yml`):** runs lint + pytest on pushes/PRs targeting `main`.
- **Release workflow (`release.yml`):** gates PyInstaller builds behind the same coverage-tested suite, uploads HTML coverage as artifacts, and on tags publishes installers, changelog PRs, and the latest coverage report to GitHub Pages.
- **Changelog generation:** `git-cliff` is invoked automatically during tag builds; avoid hand-editing `CHANGELOG.md` outside that flow.

## Support & Feedback
- File issues or feature requests via GitHub if you are using official releases.
- Internal deployments should surface questions (logs, error codes, exports) to the security tooling team so regressions can be reproduced quickly.
- Need deeper operational guidance? Start with the user manuals, then escalate with `--debug` logs or exported scan JSON for context.
