# Nmap GUI Discovery & Rating Tool

[![CI](https://github.com/unagi/rogue-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/unagi/rogue-finder/actions/workflows/ci.yml)
[![Release Builds](https://github.com/unagi/rogue-finder/actions/workflows/pyinstaller.yml/badge.svg)](https://github.com/unagi/rogue-finder/actions/workflows/pyinstaller.yml)
[![Latest Release](https://img.shields.io/github/v/release/unagi/rogue-finder?sort=semver)](https://github.com/unagi/rogue-finder/releases)

PySide6 desktop application that orchestrates lightweight Nmap discovery jobs, ranks hosts via a transparent heuristic model, and exports audit-friendly evidence so analysts can focus commercial scanners where it matters most.

**Highlights**
- ICMP, targeted port, OS, and safe-script phases launched through the local `nmap` binary (never bundled).
- Cross-platform (Windows/macOS/Linux) with PyInstaller packaging artifacts published by GitHub Actions.
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

Generate a fresh template anytime:
```bash
python -m nmap_gui.config --write-default ./rogue-finder.config.yaml
```

## Architecture Snapshot
For the full component map see [`docs/architecture_overview.md`](docs/architecture_overview.md). At a high level:

- `src/nmap_gui/main.py` boots `QApplication`, parses CLI flags, and shows `MainWindow`.
- Widgets under `src/nmap_gui/gui/` collect targets, display results, and emit `ScanConfig` objects without blocking the GUI thread.
- `src/nmap_gui/scan_manager.py` and `cancel_token.py` fan-out jobs to a `ProcessPoolExecutor` using the `spawn` context so Windows/macOS builds behave consistently.
- `src/nmap_gui/nmap_runner.py` executes ICMP/port/OS/safe-script phases, adapts to privilege limitations, and parses XML into `models.HostScanResult`.
- `rating.py`, `exporters.py`, and `job_eta.py` provide scoring, CSV/JSON output, and ETA calculations consumed by the GUI and tests.

## Documentation Hub
- Discovery/diagnostics command matrix: [`docs/scan_execution.md`](docs/scan_execution.md)
- Architecture deep dive: [`docs/architecture_overview.md`](docs/architecture_overview.md)
- User manuals (EN/JA): see [Quick Links](#quick-links)
- Agent/developer process notes: [`AGENTS.md`](AGENTS.md)
- Release notes & automation details: [`CHANGELOG.md`](CHANGELOG.md) and [Release Builds workflow](https://github.com/unagi/rogue-finder/actions/workflows/pyinstaller.yml)

## Development Guide
The repo standardizes on uv + Poe for reproducible environments.

- **Environment setup:** `uv venv && source .venv/bin/activate`, then `uv pip install -r requirements-dev.txt`.
- **Tooling:** `poe lint` (backs `ruff check src tests`), `poe test` (runs `uv run pytest --spec`).
- **Optional helpers:** `uv tool install poethepoet && uv tool update-shell` to expose the `poe` shim globally.
- **Safe-script fixtures & XML parsing tests** already live in `tests/`; add coverage whenever rating or scan behavior changes.

### CI & Release Automation
- **CI workflow (`ci.yml`):** runs lint + pytest on pushes/PRs targeting `main`.
- **Release Builds workflow (`pyinstaller.yml`):** produces Windows artifacts on every push to `main`, and both Windows/macOS packages plus changelog PRs for annotated tags or manual dispatches.
- **Changelog generation:** `git-cliff` is invoked automatically during tag builds; avoid hand-editing `CHANGELOG.md` outside that flow.

## Support & Feedback
- File issues or feature requests via GitHub if you are using official releases.
- Internal deployments should surface questions (logs, error codes, exports) to the security tooling team so regressions can be reproduced quickly.
- Need deeper operational guidance? Start with the user manuals, then escalate with `--debug` logs or exported scan JSON for context.
