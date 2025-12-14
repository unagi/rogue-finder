from multiprocessing import get_context

from nmap_gui import scan_executor
from nmap_gui.infrastructure.config import get_settings
from nmap_gui.models import HostScanResult, ScanConfig, ScanLogEvent, ScanMode


def test_scan_job_executor_runs_targets(monkeypatch):
    monkeypatch.setattr(scan_executor, "_should_use_threads", lambda: True)

    def fake_run_full_scan(*args, **kwargs):
        target = args[0]
        log_callback = args[3]
        if log_callback:
            log_callback(
                ScanLogEvent(
                    target=target,
                    phase=None,
                    stream="stdout",
                    line=f"log:{target}",
                )
            )
        return HostScanResult(target=target)

    monkeypatch.setattr(scan_executor, "run_full_scan", fake_run_full_scan)

    executor = scan_executor.ScanJobExecutor(settings=get_settings(), context=get_context("spawn"))
    config = ScanConfig(targets=["alpha", "beta", "alpha"], scan_modes={ScanMode.ICMP})

    results: list[str] = []
    logs: list[str] = []
    progress: list[tuple[int, int]] = []

    callbacks = scan_executor.ScanJobCallbacks(
        on_progress=lambda done, total: progress.append((done, total)),
        on_result=lambda result: results.append(result.target),
        on_log=lambda event: logs.append(event.line),
    )

    executor.run(config, callbacks)

    assert results == ["alpha", "beta"]
    assert progress[-1] == (2, 2)
    assert sorted(logs) == ["log:alpha", "log:beta"]


def test_scan_job_executor_emits_error(monkeypatch):
    monkeypatch.setattr(scan_executor, "_should_use_threads", lambda: True)

    def fake_run_full_scan(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(scan_executor, "run_full_scan", fake_run_full_scan)

    executor = scan_executor.ScanJobExecutor(settings=get_settings(), context=get_context("spawn"))
    config = ScanConfig(targets=["alpha"], scan_modes={ScanMode.ICMP})

    errors: list[object] = []

    callbacks = scan_executor.ScanJobCallbacks(on_error=lambda error: errors.append(error))

    executor.run(config, callbacks)

    assert errors and errors[0].code == scan_executor.ERROR_SCAN_CRASHED.code
