"""Wrapper utilities for invoking nmap as a subprocess."""
from __future__ import annotations

import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Sequence, Set

from multiprocessing.synchronize import Event as MpEvent

from .models import HostScanResult, ScanMode
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
    )
    if proc.returncode not in (0, 1):
        raise NmapExecutionError(proc.stderr.strip() or "nmap execution failed")
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
    errors: List[str] = []

    try:
        if cancel_event and cancel_event.is_set():
            errors.append("Scan aborted")
            result.errors = errors
            return apply_rating(result)
        if ScanMode.ICMP in scan_modes:
            xml_text = run_nmap(["nmap", "-sn", "-PE", target])
            result.is_alive = parse_icmp_alive(xml_text)
        if cancel_event and cancel_event.is_set():
            errors.append("Scan aborted")
            result.errors = errors
            return apply_rating(result)

        if ScanMode.PORTS in scan_modes and (result.is_alive or ScanMode.ICMP not in scan_modes):
            port_list = ",".join(str(p) for p in PORT_SCAN_LIST)
            xml_text = run_nmap(["nmap", "-sS", "-p", port_list, target, "-T4"])
            result.open_ports = parse_open_ports(xml_text)
            result.high_ports = [p for p in result.open_ports if p >= 50000]
        if cancel_event and cancel_event.is_set():
            errors.append("Scan aborted")
            result.errors = errors
            return apply_rating(result)

        if ScanMode.OS in scan_modes and (result.is_alive or ScanMode.ICMP not in scan_modes):
            xml_text = run_nmap(["nmap", "-O", "-Pn", target])
            os_guess, accuracy = parse_os_guess(xml_text)
            result.os_guess = os_guess
            result.os_accuracy = accuracy
        if cancel_event and cancel_event.is_set():
            errors.append("Scan aborted")
            result.errors = errors
            return apply_rating(result)

    except NmapNotInstalledError as exc:
        errors.append(str(exc))
    except (subprocess.TimeoutExpired, NmapExecutionError) as exc:
        errors.append(str(exc))
    finally:
        result.errors = errors

    rated = apply_rating(result)
    return rated
