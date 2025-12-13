"""Wrapper utilities for invoking nmap as a subprocess."""
from __future__ import annotations

import ipaddress
import logging
import os
import shlex
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from multiprocessing.synchronize import Event as MpEvent
from threading import Thread

from .config import DEFAULT_SETTINGS, AppSettings, get_settings
from .error_codes import (
    ERROR_NMAP_FAILED,
    ERROR_NMAP_NOT_FOUND,
    ERROR_NMAP_TIMEOUT,
    ERROR_SCAN_ABORTED,
    build_error,
)
from .models import ErrorRecord, HostScanResult, SafeScanReport, ScanLogEvent, ScanMode
from .rating import apply_rating

LOGGER = logging.getLogger(__name__)
DEFAULT_TIMEOUT = int(DEFAULT_SETTINGS["scan"]["default_timeout_seconds"])  # seconds per phase
PORT_SCAN_LIST = list(DEFAULT_SETTINGS["scan"]["port_scan_list"])

_PRIVILEGED_SCAN_PATTERNS = (
    "requires root privileges",
    "requires administrator privileges",
    "requires privileged access",
)

if os.name == "nt":  # pragma: no cover - Windows-only initialization
    _WINDOWS_STARTUPINFO = subprocess.STARTUPINFO()
    _WINDOWS_STARTUPINFO.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
    _WINDOWS_CREATION_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
else:
    _WINDOWS_STARTUPINFO = None
    _WINDOWS_CREATION_FLAGS = 0


class NmapExecutionError(RuntimeError):
    """Raised when a subprocess invocation fails."""


class NmapNotInstalledError(RuntimeError):
    """Raised when nmap binary is not on PATH."""


def _is_macos() -> bool:
    return sys.platform == "darwin"


def _has_root_privileges() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        return geteuid() == 0
    return True


def ensure_nmap_available() -> str:
    path = shutil.which("nmap")
    if not path:
        raise NmapNotInstalledError(
            "nmap binary was not found on PATH. Install nmap and try again."
        )
    return path


def run_nmap(
    args: Sequence[str],
    timeout: int = DEFAULT_TIMEOUT,
    log_callback: Callable[[ScanLogEvent], None] | None = None,
    log_target: str | None = None,
    log_phase: ScanMode | None = None,
) -> str:
    ensure_nmap_available()
    process_args = [*args, "-oX", "-"]
    LOGGER.debug("Executing nmap: %s", " ".join(process_args))
    proc = subprocess.Popen(
        process_args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
        universal_newlines=True,
        startupinfo=_WINDOWS_STARTUPINFO,
        creationflags=_WINDOWS_CREATION_FLAGS,
    )

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    def _pump_stream(stream, collector, stream_name: str) -> None:
        try:
            if stream is None:
                return
            for line in stream:
                collector.append(line)
                if log_callback and log_target:
                    log_callback(
                        ScanLogEvent(
                            target=log_target,
                            phase=log_phase,
                            stream=stream_name,
                            line=line.rstrip("\n"),
                        )
                    )
        finally:
            if stream is not None:
                stream.close()

    stdout_thread = Thread(
        target=_pump_stream,
        args=(proc.stdout, stdout_chunks, "stdout"),
        name="nmap-stdout",
        daemon=True,
    )
    stderr_thread = Thread(
        target=_pump_stream,
        args=(proc.stderr, stderr_chunks, "stderr"),
        name="nmap-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
        raise

    stdout_thread.join()
    stderr_thread.join()

    if proc.returncode != 0:
        detail = "".join(stderr_chunks).strip() or f"nmap exited with status {proc.returncode}"
        raise NmapExecutionError(detail)
    return "".join(stdout_chunks)


def _extract_host_key(host_node: ET.Element, default: str) -> str:
    for address in host_node.findall("address"):
        addrtype = address.attrib.get("addrtype")
        if addrtype in {"ipv4", "ipv6"}:
            addr = address.attrib.get("addr")
            if addr:
                return addr
    hostname = host_node.find("hostnames/hostname")
    if hostname is not None:
        name = hostname.attrib.get("name")
        if name:
            return name
    return default


def parse_icmp_hosts(xml_text: str, default_target: str) -> dict[str, bool]:
    """Return a mapping of host identifier -> ICMP reachability."""

    hosts: dict[str, bool] = {}
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        state = host.find("status")
        if state is None or state.attrib.get("state") != "up":
            continue
        key = _extract_host_key(host, default_target)
        hosts[key] = True
    return hosts


def parse_open_ports_by_host(xml_text: str, default_target: str) -> dict[str, list[int]]:
    """Return a mapping of host identifier -> sorted list of open ports."""

    root = ET.fromstring(xml_text)
    ports_by_host: dict[str, list[int]] = {}
    for host in root.findall("host"):
        key = _extract_host_key(host, default_target)
        ports: list[int] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is not None and state.attrib.get("state") == "open":
                portid = port.attrib.get("portid")
                if portid:
                    ports.append(int(portid))
        ports_by_host[key] = sorted(set(ports))
    return ports_by_host


def parse_os_guesses_by_host(
    xml_text: str, default_target: str
) -> dict[str, tuple[str, int | None]]:
    """Return a mapping of host identifier -> (guess, accuracy)."""

    root = ET.fromstring(xml_text)
    guesses: dict[str, tuple[str, int | None]] = {}
    for host in root.findall("host"):
        key = _extract_host_key(host, default_target)
        os_element = host.find("os/osmatch")
        name = "Unknown"
        accuracy_val: int | None = None
        if os_element is not None:
            name = os_element.attrib.get("name", "Unknown")
            accuracy = os_element.attrib.get("accuracy")
            accuracy_val = int(accuracy) if accuracy else None
        guesses[key] = (name, accuracy_val)
    return guesses


def run_full_scan(
    target: str,
    scan_modes: set[ScanMode],
    cancel_event: MpEvent | None = None,
    log_callback: Callable[[ScanLogEvent], None] | None = None,
    settings: AppSettings | None = None,
    custom_port_list: Sequence[int] | None = None,
    timeout_override: int | None = None,
    detail_label: str = "fast",
) -> list[HostScanResult]:
    runner = _FullScanRunner(
        target=target,
        scan_modes=scan_modes,
        cancel_event=cancel_event,
        log_callback=log_callback,
        settings=settings,
        custom_port_list=custom_port_list,
        timeout_override=timeout_override,
        detail_label=detail_label,
    )
    return runner.run()


class _FullScanRunner:
    def __init__(
        self,
        *,
        target: str,
        scan_modes: set[ScanMode],
        cancel_event: MpEvent | None,
        log_callback: Callable[[ScanLogEvent], None] | None,
        settings: AppSettings | None,
        custom_port_list: Sequence[int] | None,
        timeout_override: int | None,
        detail_label: str,
    ) -> None:
        self.target = target
        self.scan_modes = scan_modes
        self.cancel_event = cancel_event
        self.log_callback = log_callback
        self.app_settings = settings or get_settings()
        self.scan_settings = self.app_settings.scan
        self.rating_settings = self.app_settings.rating
        self.custom_port_list = custom_port_list
        self.phase_timeout = timeout_override or self.scan_settings.default_timeout_seconds
        self.detail_label = detail_label
        self.detail_timestamp = datetime.now(UTC).isoformat()
        self.errors: list[ErrorRecord] = []
        self.host_results: dict[str, HostScanResult] = {}
        self.mac_without_root = _is_macos() and not _has_root_privileges()

    def run(self) -> list[HostScanResult]:
        try:
            if self._was_cancelled():
                return self._handle_cancel()
            has_icmp_alive = self._run_icmp_phase()
            if self._was_cancelled():
                return self._handle_cancel()
            self._run_port_phase(has_icmp_alive)
            if self._was_cancelled():
                return self._handle_cancel()
            self._run_os_phase(has_icmp_alive)
            if self._was_cancelled():
                return self._handle_cancel()
        except NmapNotInstalledError:
            self.errors.append(build_error(ERROR_NMAP_NOT_FOUND))
        except subprocess.TimeoutExpired as exc:
            timeout_value = exc.timeout if getattr(exc, "timeout", None) else self.phase_timeout
            self.errors.append(build_error(ERROR_NMAP_TIMEOUT, timeout=timeout_value))
        except NmapExecutionError as exc:
            self.errors.append(build_error(ERROR_NMAP_FAILED, detail=str(exc)))
        return self._finalize()

    def _run_icmp_phase(self) -> bool:
        if ScanMode.ICMP not in self.scan_modes:
            return False
        icmp_args = self._icmp_args()
        xml_text = self._run_phase(icmp_args, ScanMode.ICMP)
        try:
            alive_hosts = parse_icmp_hosts(xml_text, self.target)
        except ET.ParseError as exc:
            raise NmapExecutionError(f"Failed to parse ICMP XML: {exc}") from exc
        for host_key in alive_hosts:
            self._ensure_host(host_key).is_alive = True
        return bool(alive_hosts)

    def _icmp_args(self) -> list[str]:
        if self.mac_without_root:
            self._emit_log(
                "macOS without root privileges detected - using TCP ping scan (-PA80,443).",
                phase=ScanMode.ICMP,
            )
            return ["nmap", "-sn", "-PA80,443", self.target, "-T4"]
        return ["nmap", "-sn", "-PE", self.target]

    def _run_port_phase(self, has_icmp_alive: bool) -> None:
        if not self._should_scan_ports(has_icmp_alive):
            return
        selected_ports = self.custom_port_list or self.scan_settings.port_scan_list
        port_list = ",".join(str(p) for p in selected_ports)
        port_args = self._port_scan_args(port_list)
        xml_text = self._execute_port_scan(port_args, port_list)
        try:
            port_map = parse_open_ports_by_host(xml_text, self.target)
        except ET.ParseError as exc:
            raise NmapExecutionError(f"Failed to parse port scan XML: {exc}") from exc
        for host_key, ports in port_map.items():
            host_result = self._ensure_host(host_key)
            host_result.is_alive = True
            host_result.open_ports = ports
            host_result.high_ports = [p for p in ports if p >= self.scan_settings.high_port_minimum]

    def _should_scan_ports(self, has_icmp_alive: bool) -> bool:
        return ScanMode.PORTS in self.scan_modes and (
            has_icmp_alive or ScanMode.ICMP not in self.scan_modes
        )

    def _port_scan_args(self, port_list: str) -> list[str]:
        args = ["nmap", "-sS", "-p", port_list, self.target, "-T4"]
        if self.mac_without_root:
            args[1] = "-sT"
            self._emit_log(
                "macOS without root privileges detected - using TCP connect scan (-sT).",
                phase=ScanMode.PORTS,
            )
        return args

    def _execute_port_scan(self, port_args: list[str], port_list: str) -> str:
        try:
            return self._run_phase(port_args, ScanMode.PORTS)
        except NmapExecutionError as exc:
            if not _requires_privileged_scan(str(exc)):
                raise
            LOGGER.info(
                "SYN scan requires elevated privileges; retrying with TCP connect scan (-sT)."
            )
            self._emit_log(
                "SYN scan requires elevated privileges; falling back to TCP connect scan (-sT).",
                phase=ScanMode.PORTS,
            )
            fallback_args = ["nmap", "-sT", "-p", port_list, self.target, "-T4"]
            return self._run_phase(fallback_args, ScanMode.PORTS)

    def _run_os_phase(self, has_icmp_alive: bool) -> None:
        should_scan_os = ScanMode.OS in self.scan_modes and (
            has_icmp_alive or ScanMode.ICMP not in self.scan_modes
        )
        if not should_scan_os:
            return
        if self.mac_without_root:
            self._emit_log(
                "Skipping OS detection because macOS GUI builds run without root privileges.",
                phase=ScanMode.OS,
            )
            return
        xml_text = self._run_phase(["nmap", "-O", "-Pn", self.target], ScanMode.OS)
        try:
            os_map = parse_os_guesses_by_host(xml_text, self.target)
        except ET.ParseError as exc:
            raise NmapExecutionError(f"Failed to parse OS detection XML: {exc}") from exc
        for host_key, (guess, accuracy) in os_map.items():
            host_result = self._ensure_host(host_key)
            host_result.is_alive = True
            host_result.os_guess = guess
            host_result.os_accuracy = accuracy

    def _run_phase(self, args: Sequence[str], phase: ScanMode | None) -> str:
        return run_nmap(
            args,
            timeout=self.phase_timeout,
            log_callback=self.log_callback,
            log_target=self.target,
            log_phase=phase,
        )

    def _ensure_host(self, host_key: str) -> HostScanResult:
        if host_key not in self.host_results:
            self.host_results[host_key] = HostScanResult(target=host_key)
        return self.host_results[host_key]

    def _finalize(self) -> list[HostScanResult]:
        if self.host_results:
            rated: list[HostScanResult] = []
            for item in self.host_results.values():
                item.errors = list(self.errors)
                item.detail_level = self.detail_label
                item.detail_updated_at = self.detail_timestamp
                rated.append(apply_rating(item, self.rating_settings))
            return rated
        if self.errors:
            placeholder = HostScanResult(
                target=self.target,
                errors=list(self.errors),
                is_placeholder=True,
                detail_level=self.detail_label,
                detail_updated_at=self.detail_timestamp,
            )
            return [apply_rating(placeholder, self.rating_settings)]
        if not _is_network_target(self.target):
            empty_result = HostScanResult(
                target=self.target,
                is_alive=False,
                detail_level=self.detail_label,
                detail_updated_at=self.detail_timestamp,
            )
            return [apply_rating(empty_result, self.rating_settings)]
        return []

    def _handle_cancel(self) -> list[HostScanResult]:
        if not any(err.code == ERROR_SCAN_ABORTED.code for err in self.errors):
            self.errors.append(build_error(ERROR_SCAN_ABORTED))
        return self._finalize()

    def _emit_log(self, line: str, stream: str = "info", phase: ScanMode | None = None) -> None:
        if not self.log_callback:
            return
        self.log_callback(
            ScanLogEvent(
                target=self.target,
                phase=phase,
                stream=stream,
                line=line,
            )
        )

    def _was_cancelled(self) -> bool:
        return bool(self.cancel_event and self.cancel_event.is_set())


def _format_cli_command(args: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in args)


def run_safe_script_scan(
    target: str,
    timeout: int | None = None,
    settings: AppSettings | None = None,
) -> SafeScanReport:
    app_settings = settings or get_settings()
    safe_settings = app_settings.safe_scan
    effective_timeout = timeout if timeout is not None else safe_settings.timeout_seconds
    started_at = datetime.now(UTC)
    base_args = ["nmap", "--noninteractive", "-sV", "--script", "safe", target, "-T4"]
    stdout = ""
    stderr = ""
    exit_code: int | None = None
    errors: list[ErrorRecord] = []
    try:
        ensure_nmap_available()
        process_args = [*base_args, "-oN", "-"]
        LOGGER.debug("Executing safe script scan: %s", " ".join(process_args))
        proc = subprocess.run(
            process_args,
            check=False,
            text=True,
            capture_output=True,
            timeout=effective_timeout,
            stdin=subprocess.DEVNULL,
            startupinfo=_WINDOWS_STARTUPINFO,
            creationflags=_WINDOWS_CREATION_FLAGS,
        )
        stdout = proc.stdout
        stderr = proc.stderr
        exit_code = proc.returncode
        if proc.returncode != 0:
            detail = stderr.strip() or f"nmap exited with status {proc.returncode}"
            errors.append(build_error(ERROR_NMAP_FAILED, detail=detail))
    except NmapNotInstalledError:
        errors.append(build_error(ERROR_NMAP_NOT_FOUND))
    except subprocess.TimeoutExpired as exc:
        timeout_value = exc.timeout if getattr(exc, "timeout", None) else effective_timeout
        errors.append(build_error(ERROR_NMAP_TIMEOUT, timeout=timeout_value))
    except Exception as exc:
        errors.append(build_error(ERROR_NMAP_FAILED, detail=str(exc)))

    finished_at = datetime.now(UTC)
    return SafeScanReport(
        target=target,
        command=_format_cli_command(base_args),
        started_at=started_at,
        finished_at=finished_at,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        errors=errors,
    )


def _requires_privileged_scan(detail: str | None) -> bool:
    if not detail:
        return False
    lowered = detail.lower()
    return any(pattern in lowered for pattern in _PRIVILEGED_SCAN_PATTERNS)


def _is_network_target(target: str) -> bool:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return network.num_addresses > 1
