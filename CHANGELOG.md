# Changelog

All notable changes to this project are documented here. The file is regenerated automatically by git-cliff based on commit history and pull request titles.
## [Unreleased]


### Features
- Add UAC manifest and noninteractive safe scan (13d36ea)
- Add YAML-based runtime configuration (50dd332)
- Add persistent GUI state storage (62b726b)
- Add lint task and PR CI workflow (d5c97be)


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



