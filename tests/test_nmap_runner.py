import io
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import pytest

from nmap_gui import nmap_runner
from nmap_gui.models import ScanMode

MAC_WITHOUT_ROOT = nmap_runner._is_macos() and not nmap_runner._has_root_privileges()
EXPECTED_CIDR_HOSTS = 2


ICMP_XML = """
<nmaprun>
  <host>
    <status state="up" reason="echo-reply" />
    <address addr="127.0.0.1" addrtype="ipv4" />
  </host>
</nmaprun>
""".strip()

PORT_XML = """
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/></port>
      <port protocol="tcp" portid="22"><state state="open"/></port>
      <port protocol="tcp" portid="445"><state state="filtered"/></port>
      <port protocol="tcp" portid="80"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>
""".strip()

OS_XML = """
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4" />
    <os>
      <osmatch name="Windows 10" accuracy="98" />
    </os>
  </host>
</nmaprun>
""".strip()

OS_XML_UNKNOWN = """
<nmaprun>
  <host>
    <os>
    </os>
  </host>
</nmaprun>
""".strip()

ICMP_HOSTNAME_XML = """
<nmaprun>
  <host>
    <status state="up" />
    <hostnames>
      <hostname name="test-host" />
    </hostnames>
  </host>
</nmaprun>
""".strip()

ICMP_MIXED_XML = """
<nmaprun>
  <host>
    <status state="down" />
    <address addr="192.0.2.1" addrtype="ipv4" />
  </host>
  <host>
    <status state="up" />
    <address addr="192.0.2.2" addrtype="ipv4" />
  </host>
</nmaprun>
""".strip()


def test_parse_icmp_hosts_detects_up_host():
    assert nmap_runner.parse_icmp_hosts(ICMP_XML, "127.0.0.1") == {"127.0.0.1": True}


def test_parse_open_ports_by_host_returns_sorted_unique_list():
    assert nmap_runner.parse_open_ports_by_host(PORT_XML, "127.0.0.1") == {
        "127.0.0.1": [22, 80]
    }


def test_parse_os_guesses_by_host_reads_name_and_accuracy():
    assert nmap_runner.parse_os_guesses_by_host(OS_XML, "127.0.0.1") == {
        "127.0.0.1": ("Windows 10", 98)
    }


def test_parse_os_guesses_by_host_defaults_when_missing():
    assert nmap_runner.parse_os_guesses_by_host(OS_XML_UNKNOWN, "127.0.0.1") == {
        "127.0.0.1": ("Unknown", None)
    }


def test_parse_icmp_hosts_handles_hostnames():
    assert nmap_runner.parse_icmp_hosts(ICMP_HOSTNAME_XML, "fallback") == {"test-host": True}


def test_parse_icmp_hosts_skips_down_hosts():
    result = nmap_runner.parse_icmp_hosts(ICMP_MIXED_XML, "fallback")
    assert result == {"192.0.2.2": True}


def test_ensure_nmap_available_raises_when_missing(monkeypatch):
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda _: None)
    with pytest.raises(nmap_runner.NmapNotInstalledError):
        nmap_runner.ensure_nmap_available()


def test_ensure_nmap_available_returns_path(monkeypatch):
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda _: "/usr/bin/nmap")
    assert nmap_runner.ensure_nmap_available() == "/usr/bin/nmap"


def test_run_nmap_raises_on_nonzero_exit(monkeypatch):
    class FakeProcess:
        def __init__(self):
            self.returncode = 1
            self.stdout = io.StringIO("")
            self.stderr = io.StringIO("permission denied\n")

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            # No-op: tests never send SIGKILL, but method must exist for subprocess API compatibility.
            pass

    created = {"count": 0}

    def fake_popen(*args, **kwargs):
        created["count"] += 1
        return FakeProcess()

    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "Popen", fake_popen)

    with pytest.raises(nmap_runner.NmapExecutionError):
        nmap_runner.run_nmap(["nmap", "-sS", "127.0.0.1"])
    assert created["count"] == 1


def test_run_nmap_streams_output_and_logs(monkeypatch):
    class FakeProcess:
        def __init__(self):
            self.returncode = 0
            self.stdout = io.StringIO("line1\nline2\n")
            self.stderr = io.StringIO("warn\n")

        def wait(self, timeout=None):
            self.timeout = timeout
            return self.returncode

        def kill(self):
            self.killed = True

    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())

    events: list[nmap_runner.ScanLogEvent] = []
    expected_event_count = 3
    output = nmap_runner.run_nmap(
        ["nmap", "-sn", "target"],
        log_callback=events.append,
        log_target="target",
        log_phase=ScanMode.ICMP,
    )

    assert output.strip().splitlines() == ["line1", "line2"]
    assert len(events) == expected_event_count  # two stdout lines + one stderr line


def test_run_nmap_kills_process_on_timeout(monkeypatch):
    class FakeProcess:
        def __init__(self):
            self.returncode = 0
            self.stdout = io.StringIO("")
            self.stderr = io.StringIO("")
            self.killed = False

        def wait(self, timeout=None):
            raise nmap_runner.subprocess.TimeoutExpired(cmd="nmap", timeout=timeout)

        def kill(self):
            self.killed = True

    proc = FakeProcess()
    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "Popen", lambda *args, **kwargs: proc)

    with pytest.raises(nmap_runner.subprocess.TimeoutExpired):
        nmap_runner.run_nmap(["nmap", "-sn", "target"], timeout=1)
    assert proc.killed is True


def test_run_nmap_handles_missing_streams(monkeypatch):
    class FakeProcess:
        def __init__(self):
            self.returncode = 0
            self.stdout = None
            self.stderr = io.StringIO("")

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())

    assert nmap_runner.run_nmap(["nmap", "-sn", "target"]) == ""


def test_run_full_scan_converts_parse_errors_to_rf004(monkeypatch):
    def fake_run_nmap(*args, **kwargs):
        return "this is not xml"

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)
    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.ICMP})
    assert results
    assert results[0].errors
    assert results[0].errors[0].code == "RF004"


def test_run_full_scan_falls_back_to_tcp_connect_when_syn_requires_root(monkeypatch):
    calls = []

    def fake_run_nmap(args, timeout=nmap_runner.DEFAULT_TIMEOUT, **kwargs):
        calls.append(args)
        if "-sS" in args:
            raise nmap_runner.NmapExecutionError(
                "You requested a scan type which requires root privileges"
            )
        return PORT_XML

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)

    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.PORTS})

    assert results
    assert not results[0].errors
    assert results[0].open_ports == [22, 80]
    assert results[0].is_alive


def test_run_full_scan_returns_multiple_hosts_for_cidr(monkeypatch):
    icmp_xml = """
    <nmaprun>
      <host>
        <status state="up" />
        <address addr="192.0.2.11" addrtype="ipv4" />
      </host>
      <host>
        <status state="up" />
        <address addr="192.0.2.13" addrtype="ipv4" />
      </host>
    </nmaprun>
    """.strip()

    port_xml = """
    <nmaprun>
      <host>
        <address addr="192.0.2.11" addrtype="ipv4" />
        <ports>
          <port protocol="tcp" portid="22"><state state="open"/></port>
        </ports>
      </host>
      <host>
        <address addr="192.0.2.13" addrtype="ipv4" />
        <ports>
          <port protocol="tcp" portid="80"><state state="open"/></port>
        </ports>
      </host>
    </nmaprun>
    """.strip()

    os_xml = """
    <nmaprun>
      <host>
        <address addr="192.0.2.11" addrtype="ipv4" />
        <os>
          <osmatch name="Linux" accuracy="90" />
        </os>
      </host>
      <host>
        <address addr="192.0.2.13" addrtype="ipv4" />
        <os>
          <osmatch name="Windows" accuracy="80" />
        </os>
      </host>
    </nmaprun>
    """.strip()

    responses = [icmp_xml, port_xml, os_xml]

    def fake_run_nmap(*args, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)

    results = nmap_runner.run_full_scan(
        "192.0.2.0/30",
        {ScanMode.ICMP, ScanMode.PORTS, ScanMode.OS},
    )

    assert len(results) == EXPECTED_CIDR_HOSTS
    by_target = {item.target: item for item in results}
    assert by_target["192.0.2.11"].open_ports == [22]
    assert by_target["192.0.2.13"].open_ports == [80]
    if not MAC_WITHOUT_ROOT:
        assert by_target["192.0.2.11"].os_guess == "Linux"
        assert by_target["192.0.2.13"].os_guess == "Windows"


def test_run_full_scan_marks_host_alive_when_only_ports(monkeypatch):
    monkeypatch.setattr(nmap_runner, "run_nmap", lambda *args, **kwargs: PORT_XML)

    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.PORTS})

    assert results
    assert results[0].is_alive is True


def _toggle_event(trigger_after: int):
    class ToggleEvent:
        def __init__(self):
            self.calls = 0
            self.trigger_after = trigger_after
            self._flag = False

        def advance(self):
            self.calls += 1
            if self.calls >= self.trigger_after:
                self._flag = True

        def is_set(self):
            return self._flag

    return ToggleEvent()


def test_run_full_scan_respects_cancel_after_icmp(monkeypatch):
    event = _toggle_event(trigger_after=1)
    responses = [ICMP_XML]

    def fake_run_nmap(args, **kwargs):
        event.advance()
        return responses[0]

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)

    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.ICMP}, cancel_event=event)
    assert results[0].errors[0].code == nmap_runner.ERROR_SCAN_ABORTED.code


def test_run_full_scan_respects_cancel_after_ports(monkeypatch):
    event = _toggle_event(trigger_after=2)
    responses = [ICMP_XML, PORT_XML]

    def fake_run_nmap(args, **kwargs):
        response = responses.pop(0)
        event.advance()
        return response

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)

    results = nmap_runner.run_full_scan(
        "127.0.0.1",
        {ScanMode.ICMP, ScanMode.PORTS},
        cancel_event=event,
    )
    assert results[0].errors[0].code == nmap_runner.ERROR_SCAN_ABORTED.code


def test_run_full_scan_respects_cancel_after_os(monkeypatch):
    event = _toggle_event(trigger_after=3)
    responses = [ICMP_XML, PORT_XML, OS_XML]

    def fake_run_nmap(args, **kwargs):
        response = responses.pop(0)
        event.advance()
        return response

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)

    results = nmap_runner.run_full_scan(
        "127.0.0.1",
        {ScanMode.ICMP, ScanMode.PORTS, ScanMode.OS},
        cancel_event=event,
    )
    assert results[0].errors[0].code == nmap_runner.ERROR_SCAN_ABORTED.code


def test_run_full_scan_handles_missing_nmap(monkeypatch):
    def fake_run(*args, **kwargs):
        raise nmap_runner.NmapNotInstalledError("missing")

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run)

    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.ICMP})
    assert results[0].errors[0].code == nmap_runner.ERROR_NMAP_NOT_FOUND.code


def test_run_full_scan_handles_timeout(monkeypatch):
    def fake_run(*args, **kwargs):
        raise nmap_runner.subprocess.TimeoutExpired(cmd="nmap", timeout=5)

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run)

    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.ICMP})
    assert results[0].errors[0].code == nmap_runner.ERROR_NMAP_TIMEOUT.code


def test_run_full_scan_handles_port_parse_error(monkeypatch):
    monkeypatch.setattr(nmap_runner, "run_nmap", lambda *args, **kwargs: PORT_XML)

    def bad_parse(*args, **kwargs):
        raise ET.ParseError("bad")

    monkeypatch.setattr(nmap_runner, "parse_open_ports_by_host", bad_parse)

    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.PORTS})
    assert results[0].errors[0].code == nmap_runner.ERROR_NMAP_FAILED.code


def test_run_full_scan_bubbles_unprivileged_port_errors(monkeypatch):
    def fake_run(*args, **kwargs):
        raise nmap_runner.NmapExecutionError("fatal issue")

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run)
    monkeypatch.setattr(nmap_runner, "_requires_privileged_scan", lambda detail: False)

    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.PORTS})
    assert results[0].errors[0].code == nmap_runner.ERROR_NMAP_FAILED.code


def test_run_full_scan_handles_os_parse_error(monkeypatch):
    monkeypatch.setattr(nmap_runner, "run_nmap", lambda *args, **kwargs: OS_XML)

    def bad_parse(*args, **kwargs):
        raise ET.ParseError("bad")

    monkeypatch.setattr(nmap_runner, "parse_os_guesses_by_host", bad_parse)

    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.OS})
    assert results[0].errors[0].code == nmap_runner.ERROR_NMAP_FAILED.code


def test_run_full_scan_returns_empty_for_network_target(monkeypatch):
    monkeypatch.setattr(
        nmap_runner,
        "run_nmap",
        lambda *args, **kwargs: pytest.fail("No scans should run when no modes provided"),
    )

    assert nmap_runner.run_full_scan("192.0.2.0/30", set()) == []


def test_full_scan_handle_cancel_deduplicates_errors():
    runner = nmap_runner._FullScanRunner(
        target="198.51.100.1",
        scan_modes=set(),
        cancel_event=None,
        log_callback=None,
        settings=nmap_runner.get_settings(),
        custom_port_list=None,
        timeout_override=None,
        detail_label="fast",
    )
    first = runner._handle_cancel()
    second = runner._handle_cancel()
    assert len(first[0].errors) == 1
    assert len(second[0].errors) == 1


def test_run_full_scan_handles_immediate_cancel(monkeypatch):
    def fake_run_nmap(*args, **kwargs):
        raise AssertionError("run_nmap should not be called when cancelled")

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)

    class AlwaysSetEvent:
        def is_set(self):
            return True

    results = nmap_runner.run_full_scan("198.51.100.14", {ScanMode.ICMP}, cancel_event=AlwaysSetEvent())

    assert len(results) == 1
    assert results[0].errors
    assert results[0].errors[0].code == nmap_runner.ERROR_SCAN_ABORTED.code


def test_run_full_scan_returns_placeholder_for_non_network_target(monkeypatch):
    monkeypatch.setattr(
        nmap_runner,
        "run_nmap",
        lambda *args, **kwargs: pytest.fail("run_nmap should not execute for empty scan modes"),
    )

    results = nmap_runner.run_full_scan("198.51.100.20", set())

    assert len(results) == 1
    assert results[0].target == "198.51.100.20"
    assert results[0].is_alive is False


def test_run_full_scan_logs_macos_fallbacks(monkeypatch):
    responses = [ICMP_XML, PORT_XML]
    calls: list[list[str]] = []

    def fake_run_nmap(args, **kwargs):
        calls.append(args)
        return responses.pop(0)

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)
    monkeypatch.setattr(nmap_runner, "_is_macos", lambda: True)
    monkeypatch.setattr(nmap_runner, "_has_root_privileges", lambda: False)

    logs: list[nmap_runner.ScanLogEvent] = []
    results = nmap_runner.run_full_scan(
        "127.0.0.1",
        {ScanMode.ICMP, ScanMode.PORTS, ScanMode.OS},
        log_callback=logs.append,
    )

    assert len(results) == 1
    expected_command_invocations = 2
    assert len(calls) == expected_command_invocations  # OS phase skipped
    messages = [event.line for event in logs]
    assert any("TCP ping scan" in line for line in messages)
    assert any("TCP connect scan" in line for line in messages)
    assert any("Skipping OS detection" in line for line in messages)


def test_run_safe_script_scan_success(monkeypatch):
    class FakeCompleted:
        def __init__(self):
            self.stdout = "ok"
            self.stderr = ""
            self.returncode = 0

    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "run", lambda *args, **kwargs: FakeCompleted())

    report = nmap_runner.run_safe_script_scan("198.51.100.50", timeout=10)

    assert report.exit_code == 0
    assert report.errors == []
    assert "nmap" in report.command


def test_run_safe_script_scan_timeout(monkeypatch):
    def fake_run(*args, **kwargs):
        raise nmap_runner.subprocess.TimeoutExpired(cmd="nmap", timeout=kwargs.get("timeout"))

    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "run", fake_run)

    report = nmap_runner.run_safe_script_scan("198.51.100.51", timeout=5)

    assert report.errors
    assert report.errors[0].code == nmap_runner.ERROR_NMAP_TIMEOUT.code


def test_run_safe_script_scan_handles_nonzero_exit(monkeypatch):
    class FakeCompleted:
        def __init__(self):
            self.stdout = ""
            self.stderr = "boom"
            self.returncode = 2

    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "run", lambda *args, **kwargs: FakeCompleted())

    report = nmap_runner.run_safe_script_scan("198.51.100.52", timeout=5)
    assert report.errors[0].code == nmap_runner.ERROR_NMAP_FAILED.code


def test_run_safe_script_scan_handles_missing_binary(monkeypatch):
    def fake_ensure():
        raise nmap_runner.NmapNotInstalledError("missing")

    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", fake_ensure)

    report = nmap_runner.run_safe_script_scan("198.51.100.53", timeout=5)
    assert report.errors[0].code == nmap_runner.ERROR_NMAP_NOT_FOUND.code


def test_run_safe_script_scan_handles_generic_exception(monkeypatch):
    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", lambda: "/usr/bin/nmap")

    def fake_run(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(nmap_runner.subprocess, "run", fake_run)

    report = nmap_runner.run_safe_script_scan("198.51.100.54", timeout=5)
    assert report.errors[0].code == nmap_runner.ERROR_NMAP_FAILED.code


def test_requires_privileged_scan_matches_patterns():
    assert nmap_runner._requires_privileged_scan("Requires root privileges to continue")
    assert not nmap_runner._requires_privileged_scan("no issue")
    assert not nmap_runner._requires_privileged_scan(None)


def test_is_network_target_distinguishes_hosts():
    assert nmap_runner._is_network_target("192.0.2.0/30") is True
    assert nmap_runner._is_network_target("192.0.2.1") is False
    assert nmap_runner._is_network_target("not-a-network") is False


def test_format_cli_command_quotes_args():
    command = nmap_runner._format_cli_command(["nmap", "--flag", "target host"])
    assert command == "nmap --flag 'target host'"


def test_has_root_privileges_without_geteuid(monkeypatch):
    monkeypatch.setattr(nmap_runner, "os", SimpleNamespace(name="posix"))
    assert nmap_runner._has_root_privileges() is True


def test_has_root_privileges_with_geteuid(monkeypatch):
    monkeypatch.setattr(nmap_runner, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    assert nmap_runner._has_root_privileges() is True
