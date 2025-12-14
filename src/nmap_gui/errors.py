"""Centralized error descriptors and helpers."""
from __future__ import annotations

from dataclasses import dataclass

from .models import ErrorRecord


@dataclass(frozen=True)
class ErrorDescriptor:
    code: str
    message_key: str
    action_key: str


def build_error(descriptor: ErrorDescriptor, **context: object) -> ErrorRecord:
    """Create an ErrorRecord with safe stringified context."""

    str_context = {key: str(value) for key, value in context.items()}
    return ErrorRecord(
        code=descriptor.code,
        message_key=descriptor.message_key,
        action_key=descriptor.action_key,
        context=str_context,
    )


ERROR_SCAN_ABORTED = ErrorDescriptor(
    code="RF001",
    message_key="error.scan_aborted.message",
    action_key="error.scan_aborted.action",
)

ERROR_NMAP_NOT_FOUND = ErrorDescriptor(
    code="RF002",
    message_key="error.nmap_not_found.message",
    action_key="error.nmap_not_found.action",
)

ERROR_NMAP_TIMEOUT = ErrorDescriptor(
    code="RF003",
    message_key="error.nmap_timeout.message",
    action_key="error.nmap_timeout.action",
)

ERROR_NMAP_FAILED = ErrorDescriptor(
    code="RF004",
    message_key="error.nmap_failed.message",
    action_key="error.nmap_failed.action",
)

ERROR_WORKER_POOL_FAILED = ErrorDescriptor(
    code="RF005",
    message_key="error.worker_pool_failed.message",
    action_key="error.worker_pool_failed.action",
)

ERROR_SCAN_CRASHED = ErrorDescriptor(
    code="RF006",
    message_key="error.scan_crashed.message",
    action_key="error.scan_crashed.action",
)

__all__ = [
    "ERROR_NMAP_FAILED",
    "ERROR_NMAP_NOT_FOUND",
    "ERROR_NMAP_TIMEOUT",
    "ERROR_SCAN_ABORTED",
    "ERROR_SCAN_CRASHED",
    "ERROR_WORKER_POOL_FAILED",
    "ErrorDescriptor",
    "build_error",
]
