# Scan Execution Reference

This document describes how each user-facing action in Rogue Finder translates into concrete `nmap` invocations. It serves as the canonical reference for engineers and documentation writers who need to understand what happens under the hood when the GUI launches discovery or diagnostics jobs.

## Fast Discovery

Triggered by the **Start** button in the main window.

- **Scan modes:** ICMP discovery and targeted TCP port scan.
- **Targets:** Every entry supplied in the target text box is scanned in a single batch.
- **Port list:** `settings.scan.fast_port_scan_list` (defaults to a trimmed subset of high-signal ports).
- **Timeout:** `settings.scan.default_timeout_seconds` per phase (default 300 seconds).

CLI equivalents (per target):

1. ICMP host discovery  
   `nmap -sn -PE <target>`
   - macOS without root privileges automatically downgrades to TCP ping: `nmap -sn -PA80,443 <target> -T4`.
2. TCP SYN port scan  
   `nmap -sS -p <comma-separated fast ports> <target> -T4`
   - macOS without root privileges (or any platform that reports “requires elevated privileges”) falls back to `-sT`.

OS fingerprinting is skipped for fast discovery to keep the workflow lightweight.

### Relevant Settings

- `scan.fast_port_scan_list` – list of TCP ports used for the fast phase.
- `scan.default_timeout_seconds` – phase timeout applied to ICMP and the fast TCP sweep.

## Advanced Discovery

Triggered by the **Run Advanced Scan** button after selecting rows in the results table.

- **Scan modes:** Always performs a targeted TCP port scan; optionally adds OS fingerprinting for rows that have the OS checkbox enabled.
- **Targets:** Only the selected rows; OS-enabled rows are split into a separate `ScanConfig` so elevated privileges can be enforced independently.
- **Port list:** `settings.scan.port_scan_list` (the full weighted list used by the rating engine).
- **Timeout / parallelism:** `settings.scan.advanced_timeout_seconds` per phase (default 600 seconds), `settings.scan.advanced_max_parallel` simultaneous targets (default 4).

CLI equivalents:

1. TCP SYN (or TCP connect when necessary) against the full port list:  
   `nmap -sS -p <comma-separated advanced ports> <target> -T4`
2. Optional OS fingerprinting when the OS checkbox is enabled **and** the process has the required privileges:  
   `nmap -O -Pn <target>`
   - macOS GUI builds run without root, so OS detection is skipped unless the CLI is re-launched via `sudo`.

### Relevant Settings

- `scan.port_scan_list` – base set of advanced ports.
- `scan.advanced_timeout_seconds` – timeout applied to the high-detail port and OS phases.
- `scan.advanced_max_parallel` – number of simultaneous targets handed to `ProcessPoolExecutor`.

## Safe Diagnostics

Triggered by the **Run Safe Diagnostics** button and processed with bounded concurrency to avoid overwhelming the host.

- **Scan modes:** `nmap --script safe` with service detection.
- **Targets:** Each selected row runs in its own job; the GUI queues them and emits progress updates while running up to `settings.safe_scan.max_parallel` targets in parallel (default 2).
- **Timeout:** `settings.safe_scan.timeout_seconds` (default 900 seconds) plus a matching progress-bar baseline defined by `settings.safe_scan.default_duration_seconds` (default 600 seconds).

CLI equivalent:  
`nmap --noninteractive -sV --script safe <target> -T4 -oN -`

Reports include the exact command string, stdout, stderr, exit code, and any structured `ErrorRecord`s so analysts can archive the result.

### Relevant Settings

- `safe_scan.timeout_seconds` – hard timeout passed to `subprocess.run`.
- `safe_scan.default_duration_seconds` – baseline used for ETA / progress smoothing.
- `safe_scan.max_parallel` – number of concurrent diagnostics workers.

## Platform Notes

- macOS GUI builds run without elevated privileges, so ICMP (`-PE`), SYN (`-sS`), and OS (`-O`) phases degrade to TCP-only tactics automatically. Users who need full fidelity should run the CLI via `sudo python -m nmap_gui.main --debug`.
- Windows and Linux builds behave identically when executed with appropriate privileges. When a SYN scan reports privileged requirements at runtime, Rogue Finder retries the ports phase with `-sT` to keep the workflow running.
