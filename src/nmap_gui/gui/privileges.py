"""Privilege checking helpers."""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path
from typing import Callable, Set

from PySide6.QtWidgets import QMessageBox, QWidget

from ..models import ScanMode

Translator = Callable[[str], str]


def has_required_privileges(modes: Set[ScanMode]) -> bool:
    if ScanMode.OS not in modes:
        return True
    if os.name == "nt":
        return True
    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid):
        return True
    return geteuid() == 0


def privileged_launch_command() -> str:
    if getattr(sys, "frozen", False):
        executable = Path(sys.executable).resolve()
        return f"sudo {shlex.quote(str(executable))}"
    python = sys.executable or "python3"
    python_path = shlex.quote(str(Path(python).resolve()))
    return f"sudo {python_path} -m nmap_gui.main --debug"


def show_privileged_hint(parent: QWidget, translator: Translator) -> None:
    command = privileged_launch_command()
    QMessageBox.information(
        parent,
        translator("privileged_os_required_title"),
        translator("privileged_os_required_body").format(command=command),
    )
