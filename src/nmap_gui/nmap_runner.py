"""Wrapper utilities for invoking nmap as a subprocess."""
from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Sequence, Set, Tuple

from multiprocessing.synchronize import Event as MpEvent

from .error_codes import (
    ERROR_NMAP_FAILED,
    ERROR_NMAP_NOT_FOUND,
    ERROR_NMAP_TIMEOUT,
    ERROR_SCAN_ABORTED,
    build_error,
)
from .models import ErrorRecord, HostScanResult, ScanMode
from .rating import apply_rating

LOGGER = logging.getLogger(__name__)
DEFAULT_TIMEOUT = 300  # seconds per phase
PORT_SCAN_LIST = [
    21,
    22,
    80,
    139,
    443,
    445,
    1433,
    3000,
    3306,
    3389,
    5432,
    5672,
    5900,
    5985,
    6379,
    8000,
    8080,
    8888,
    11211,
    15672,
    50000,
]

_PRIVILEGED_SCAN_PATTERNS = (
    "requires root privileges",
    "requires administrator privileges",
    "requires privileged access",
)

if os.name == "nt":
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


def ensure_nmap_available() -> str:
    path = shutil.which("nmap")
    if not path:
        raise NmapNotInstalledError(
            "nmap binary was not found on PATH. Install nmap and try again."
        )
    return path


def run_nmap(args: Sequence[str], timeout: int = DEFAULT_TIMEOUT) -> str:
    ensure_nmap_available()
    process_args = list(args) + ["-oX", "-"]
    LOGGER.debug("Executing nmap: %s", " ".join(process_args))
    proc = subprocess.run(
        process_args,
        check=False,
        text=True,
        capture_output=True,
        timeout=timeout,
        startupinfo=_WINDOWS_STARTUPINFO,
        creationflags=_WINDOWS_CREATION_FLAGS,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or f"nmap exited with status {proc.returncode}"
        raise NmapExecutionError(detail)
    return proc.stdout


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


def parse_icmp_hosts(xml_text: str, default_target: str) -> Dict[str, bool]:
    """Return a mapping of host identifier -> ICMP reachability."""

    hosts: Dict[str, bool] = {}
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        state = host.find("status")
        if state is None or state.attrib.get("state") != "up":
            continue
        key = _extract_host_key(host, default_target)
        hosts[key] = True
    return hosts


def parse_open_ports_by_host(xml_text: str, default_target: str) -> Dict[str, List[int]]:
    """Return a mapping of host identifier -> sorted list of open ports."""

    root = ET.fromstring(xml_text)
    ports_by_host: Dict[str, List[int]] = {}
    for host in root.findall("host"):
        key = _extract_host_key(host, default_target)
        ports: List[int] = []
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
) -> Dict[str, Tuple[str, int | None]]:
    """Return a mapping of host identifier -> (guess, accuracy)."""

    root = ET.fromstring(xml_text)
    guesses: Dict[str, Tuple[str, int | None]] = {}
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
    target: str, scan_modes: Set[ScanMode], cancel_event: MpEvent | None = None
) -> List[HostScanResult]:
    errors: List[ErrorRecord] = []
    host_results: Dict[str, HostScanResult] = {}
    has_icmp_alive = False

    def _ensure_host(host_key: str) -> HostScanResult:
        if host_key not in host_results:
            host_results[host_key] = HostScanResult(target=host_key)
        return host_results[host_key]

    def _finalize() -> List[HostScanResult]:
        if host_results:
            rated: List[HostScanResult] = []
            for item in host_results.values():
                item.errors = list(errors)
                rated.append(apply_rating(item))
            return rated
        if errors or not _is_network_target(target):
            placeholder = HostScanResult(target=target, errors=list(errors))
            return [apply_rating(placeholder)]
        return []

    def _handle_cancel() -> List[HostScanResult]:
        if not any(err.code == ERROR_SCAN_ABORTED.code for err in errors):
            errors.append(build_error(ERROR_SCAN_ABORTED))
        return _finalize()

    try:
        if cancel_event and cancel_event.is_set():
            return _handle_cancel()
        if ScanMode.ICMP in scan_modes:
            xml_text = run_nmap(["nmap", "-sn", "-PE", target])
            try:
                alive_hosts = parse_icmp_hosts(xml_text, target)
            except ET.ParseError as exc:
                raise NmapExecutionError(f"Failed to parse ICMP XML: {exc}") from exc
            for host_key in alive_hosts:
                _ensure_host(host_key).is_alive = True
            has_icmp_alive = bool(alive_hosts)
        if cancel_event and cancel_event.is_set():
            return _handle_cancel()

        should_scan_ports = ScanMode.PORTS in scan_modes and (
            has_icmp_alive or ScanMode.ICMP not in scan_modes
        )
        if should_scan_ports:
            port_list = ",".join(str(p) for p in PORT_SCAN_LIST)
            port_args = ["nmap", "-sS", "-p", port_list, target, "-T4"]
            try:
                xml_text = run_nmap(port_args)
            except NmapExecutionError as exc:
                if _requires_privileged_scan(str(exc)):
                    LOGGER.info(
                        "SYN scan requires elevated privileges; retrying with TCP connect scan (-sT)."
                    )
                    xml_text = run_nmap([
                        "nmap",
                        "-sT",
                        "-p",
                        port_list,
                        target,
                        "-T4",
                    ])
                else:
                    raise
            try:
                port_map = parse_open_ports_by_host(xml_text, target)
            except ET.ParseError as exc:
                raise NmapExecutionError(f"Failed to parse port scan XML: {exc}") from exc
            for host_key, ports in port_map.items():
                host_result = _ensure_host(host_key)
                host_result.open_ports = ports
                host_result.high_ports = [p for p in ports if p >= 50000]
        if cancel_event and cancel_event.is_set():
            return _handle_cancel()

        should_scan_os = ScanMode.OS in scan_modes and (
            has_icmp_alive or ScanMode.ICMP not in scan_modes
        )
        if should_scan_os:
            xml_text = run_nmap(["nmap", "-O", "-Pn", target])
            try:
                os_map = parse_os_guesses_by_host(xml_text, target)
            except ET.ParseError as exc:
                raise NmapExecutionError(f"Failed to parse OS detection XML: {exc}") from exc
            for host_key, (guess, accuracy) in os_map.items():
                host_result = _ensure_host(host_key)
                host_result.os_guess = guess
                host_result.os_accuracy = accuracy
        if cancel_event and cancel_event.is_set():
            return _handle_cancel()

    except NmapNotInstalledError:
        errors.append(build_error(ERROR_NMAP_NOT_FOUND))
    except subprocess.TimeoutExpired as exc:
        timeout_value = exc.timeout if getattr(exc, "timeout", None) else DEFAULT_TIMEOUT
        errors.append(build_error(ERROR_NMAP_TIMEOUT, timeout=timeout_value))
    except NmapExecutionError as exc:
        errors.append(build_error(ERROR_NMAP_FAILED, detail=str(exc)))

    return _finalize()


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
