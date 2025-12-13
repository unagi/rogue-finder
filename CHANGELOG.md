# Changelog

All notable changes to this project are documented here. The file is regenerated automatically by git-cliff based on commit history and pull request titles.
## 0.2.2 - 2025-12-13


### Documentation
- docs: update changelog for v0.2.1 (2a79ad2)
- docs: update changelog for v0.2.2 (cb941f0)



### Fixes
- Fix coverage pipeline dependencies (4184069)



### Other
- Expand tests and coverage (2f53b11)


## 0.2.1 - 2025-12-13


### CI
- ci: add sonarcloud analysis (9581443)



### Chores
- chore: add sonar config and badge (5e8693c)



### Documentation
- docs: streamline README and manuals (002d89d)



### Features
- Add GUI configuration editor (fa6bfce)
- Add coverage reporting and Pages deploy (433adaa)



### Improvements
- Improve fast ETA handling (4f90718)



### Other
- Simplify workflows and repair changelog automation (5941bd3)
- Expand Ruff lint coverage and modernize typing (4a9be3d)
- Silence Sonar hotspots and keep manuals in sync (c5b2655)
- Raise coverage floor and add tests (80c87a5)
- Skip changelog PR without PAT (3eb836d)
- Gate changelog job via env (6f23006)


## 0.2.0 - 2025-12-12


### Changes
- Enable Ruff PLR linting (f686750)



### Chores
- chore: automate changelog generation (eef3c90)



### Features
- Add UAC manifest and noninteractive safe scan (13d36ea)
- Add YAML-based runtime configuration (50dd332)
- Add persistent GUI state storage (62b726b)
- Add lint task and PR CI workflow (d5c97be)
- Add dual advanced actions and bundle platform icons (ea50b5c)
- feat: embed diagnostics viewer and report storage (6b7694e)
- feat: polish ui and packaging (8801a1f)
- feat: polish ui and packaging (dfb58e8)



### Fixes
- fix: use proper pyinstaller add-data syntax (84757d7)
- fix: add white background to app icon (a37b696)
- fix: quote pyinstaller add-data args (e1da1cd)



### Other
- Enhance staged discovery workflow (af7f525)
- Revert "feat: polish ui and packaging" (fbdac17)



### Refactors
- refactor gui architecture and fix lint (80ed39e)


## 0.1.1 - 2025-12-11


### Features
- Add safe script diagnostics workflow (9d77bc0)
- Add pseudo progress for safe diagnostics (3c01e1c)


## 0.1.0 - 2025-12-01


### Changes
- Switch macOS build to arm runner and document support (502100e)



### Features
- Add app sources and CI workflow (eeee5b8)
- Add AGENTS briefing (d32f80e)
- Add regression coverage for scan manager (a8e38e5)
- Add localization-aware errors and manuals (7eadb7d)
- Add privilege hint for OS scans (cfa38f5)



### Fixes
- Fix PyInstaller workflow conditions (e1b6d59)
- Fix entry point import when run directly (6513b45)
- Fix scan cancel event sharing (3c225b1)
- Fix pipe cancel token checks (35486ae)
- Guard BrokenProcessPool import (887bcd5)
- Fix release zipping by packaging downloaded artifacts (ac2c8e1)
- Fallback to threads on macOS to avoid RF006 (6d0df25)
- Fix release permissions and fallback to TCP connect (4790c0e)



### Improvements
- Improve table layout and sorting (2037665)
- Improve release artifacts, docs, and nmap error handling (2cdc410)



### Other
- Initial commit (46e9262)
- Replace cancel manager with pipe token (a24c2ca)
- Extract cancel token to standalone module (fde43d1)
- Use thread executor on Windows (d3d14a9)
- Emit CIDR hosts individually and add summary (c1f2421)



