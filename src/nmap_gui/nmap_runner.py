"""Wrapper utilities for invoking nmap as a subprocess."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Sequence, Set

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


def parse_icmp_alive(xml_text: str) -> bool:
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        state = host.find("status")
        if state is not None and state.attrib.get("state") == "up":
            return True
    return False


def parse_open_ports(xml_text: str) -> List[int]:
    ports: List[int] = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is not None and state.attrib.get("state") == "open":
                portid = port.attrib.get("portid")
                if portid:
                    ports.append(int(portid))
    return sorted(set(ports))


def parse_os_guess(xml_text: str) -> tuple[str, int | None]:
    root = ET.fromstring(xml_text)
    os_element = root.find("host/os/osmatch")
    if os_element is not None:
        name = os_element.attrib.get("name", "Unknown")
        accuracy = os_element.attrib.get("accuracy")
        return name, int(accuracy) if accuracy else None
    return "Unknown", None


def run_full_scan(target: str, scan_modes: Set[ScanMode], cancel_event: MpEvent | None = None) -> HostScanResult:
    result = HostScanResult(target=target)
    errors: List[ErrorRecord] = []

    try:
        if cancel_event and cancel_event.is_set():
            errors.append(build_error(ERROR_SCAN_ABORTED))
            result.errors = errors
            return apply_rating(result)
        if ScanMode.ICMP in scan_modes:
            xml_text = run_nmap(["nmap", "-sn", "-PE", target])
            try:
                result.is_alive = parse_icmp_alive(xml_text)
            except ET.ParseError as exc:
                raise NmapExecutionError(f"Failed to parse ICMP XML: {exc}") from exc
        if cancel_event and cancel_event.is_set():
            errors.append(build_error(ERROR_SCAN_ABORTED))
            result.errors = errors
            return apply_rating(result)

        if ScanMode.PORTS in scan_modes and (result.is_alive or ScanMode.ICMP not in scan_modes):
            port_list = ",".join(str(p) for p in PORT_SCAN_LIST)
            xml_text = run_nmap(["nmap", "-sS", "-p", port_list, target, "-T4"])
            try:
                result.open_ports = parse_open_ports(xml_text)
            except ET.ParseError as exc:
                raise NmapExecutionError(f"Failed to parse port scan XML: {exc}") from exc
            result.high_ports = [p for p in result.open_ports if p >= 50000]
        if cancel_event and cancel_event.is_set():
            errors.append(build_error(ERROR_SCAN_ABORTED))
            result.errors = errors
            return apply_rating(result)

        if ScanMode.OS in scan_modes and (result.is_alive or ScanMode.ICMP not in scan_modes):
            xml_text = run_nmap(["nmap", "-O", "-Pn", target])
            try:
                os_guess, accuracy = parse_os_guess(xml_text)
            except ET.ParseError as exc:
                raise NmapExecutionError(f"Failed to parse OS detection XML: {exc}") from exc
            result.os_guess = os_guess
            result.os_accuracy = accuracy
        if cancel_event and cancel_event.is_set():
            errors.append(build_error(ERROR_SCAN_ABORTED))
            result.errors = errors
            return apply_rating(result)

    except NmapNotInstalledError:
        errors.append(build_error(ERROR_NMAP_NOT_FOUND))
    except subprocess.TimeoutExpired as exc:
        timeout_value = exc.timeout if getattr(exc, "timeout", None) else DEFAULT_TIMEOUT
        errors.append(build_error(ERROR_NMAP_TIMEOUT, timeout=timeout_value))
    except NmapExecutionError as exc:
        errors.append(build_error(ERROR_NMAP_FAILED, detail=str(exc)))
    finally:
        result.errors = errors

    rated = apply_rating(result)
    return rated
