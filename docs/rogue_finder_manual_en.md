# Rogue Finder User Manual (English)

## Purpose & Audience
Rogue Finder is a cross-platform desktop utility that orchestrates lightweight Nmap discovery scans and applies a transparent scoring model so analysts can quickly decide which hosts deserve deeper commercial scanning. This manual targets operators who download the PyInstaller bundle and need a concise reference for installation, daily use, and troubleshooting.

## Capabilities Summary
- Launch ICMP ping sweeps, targeted TCP SYN port scans, and OS fingerprint probes through the locally installed `nmap` binary.
- Queue multiple targets (IPs, CIDR ranges, hostnames) and let Rogue Finder parallelize work without freezing the GUI.
- Rate each host using the heuristics described in `nmap_gui_system_spec.md`, highlight High / Medium / Low priorities, and export structured CSV or JSON files with full score breakdowns and error logs.
- Respect cancellation: you can stop the run at any time and partial results stay visible.

## Requirements & Installation
1. Install Python or simply use the provided PyInstaller binary; no interpreter is required for the packaged build.
2. Install Nmap separately and ensure the executable is discoverable on `PATH`:
   - **Windows:** download the official installer from <https://nmap.org/download.html>, install with default options, then open a new Command Prompt and confirm `nmap --version` works.
   - **macOS (arm64 build):** Releases ship Apple Silicon binaries tested on macOS 15+. Intel Macs should run from source (`python -m nmap_gui.main`) or translate via Rosetta if available. Install Nmap via `brew install nmap` or the official dmg.
   - **Linux:** install via your package manager (e.g., `sudo apt install nmap`).
3. Place the downloaded Rogue Finder binary and this manual in the same directory for convenience.

## Using the Application
1. **Start the GUI** — double-click the `rogue-finder` executable (or run `rogue-finder.exe` / `./rogue-finder`).
2. **Enter targets** — paste comma-, newline-, tab-, or semicolon-separated targets into the input field. Examples: `10.0.0.0/24`, `server01.local`, `192.168.5.10`.
3. **Select scan modes** — ICMP, Ports, and OS scans are all enabled by default. Disable phases you do not need by unchecking the boxes.
4. **Start scanning** — press **Start**. The status bar will show “Scanning…” and the progress bar tracks completed targets. Use **Stop** to cancel.
5. **Review results** — each row displays alive state, ports, OS guess, score, priority color, and any error/action guidance. High-value hosts appear first when you sort by score or priority.
6. **Export evidence** — press **Export CSV** or **Export JSON** to generate UTF-8 files. Exports include localized human-readable error text (`errors_text`) alongside structured fields, making sharing straightforward.

### Best Practices
- Keep target batches reasonable (for example, a /24 or a few dozen hosts) to avoid long-running scans or SmartScreen concerns when distributing outputs.
- Run Rogue Finder from a directory where you have write access if you plan to export reports.
- When scanning production networks, obtain the necessary approvals and avoid intrusive options beyond what Rogue Finder uses by default.

## Configuration File
Every run checks for `rogue-finder.config.yaml` in the directory you launched Rogue Finder from. If the file is missing it is generated with safe defaults; when you upgrade to a newer version the loader backfills any new keys while leaving your existing overrides untouched. Edit this YAML to tune scan timeouts and port lists (`scan` section), weighting rules for scoring (`rating`), safe-script timing heuristics (`safe_scan`), or UI row colors (`ui`). Ship a tailored copy alongside the PyInstaller binary if you want operators to start with organization-specific defaults.

## FAQ & Error Codes
Rogue Finder surfaces consistent error codes everywhere (GUI table, dialogs, exports). Use this list to decide the next action.

| Code | Message Summary | Recommended Action |
| --- | --- | --- |
| **RF001** | Scan was aborted before completion. | Restart the scan once you are ready. If you pressed **Stop**, simply re-run. |
| **RF002** | Nmap executable not found on PATH. | Install Nmap for your OS and make sure `nmap` works in a terminal, then relaunch Rogue Finder. |
| **RF003** | Nmap timed out (default 300 seconds). | Reduce the scope (fewer hosts/ports) or bump `scan.default_timeout_seconds` inside `rogue-finder.config.yaml`, then rebuild/package if you are shipping PyInstaller artifacts. |
| **RF004** | Nmap returned an execution error (stderr included). | Inspect the detail text (e.g., permissions/firewall). Adjust targets or run Rogue Finder as an administrator if required. |
| **RF005** | Worker processes stopped unexpectedly. | Rerun with fewer simultaneous targets or restart the application to reset the worker pool. |
| **RF006** | Generic scan crash (uncaught exception detail shown). | Review the error detail and recent edits. If reproducible, file an issue with steps and logs. |

## Additional Notes
- **SmartScreen warnings (Windows):** Unsigned executables often trigger Microsoft Defender SmartScreen (“Windows protected your PC”). Click “More info” and “Run anyway” only if you trust the binary source (your build or the official release). Consider signing the executable with your organization’s certificate for widespread deployment.
- **Gatekeeper quarantine (macOS):** Finder marks downloads with `com.apple.quarantine`, so double-clicking the app may display “rogue-finder cannot be opened because it is from an unidentified developer.” Open **Terminal** in the download directory and run `xattr -dr com.apple.quarantine ./rogue-finder` (replace the path as needed), or right-click → **Open** twice to whitelist the binary.
- **Antivirus exclusions:** Some security suites throttle Nmap subprocesses. If scans consistently time out, temporarily allow `nmap.exe` and `rogue-finder.exe` or run from an approved workstation.
- **Data handling:** Exported CSV/JSON files include full score breakdowns and error logs. Treat them as sensitive because they may reveal internal hostnames or service exposure.

## Support
If an issue persists after following the FAQ actions, capture the GUI screenshot or export plus the error code and contact your internal security tooling team or open a GitHub issue with the artifact version tag.
