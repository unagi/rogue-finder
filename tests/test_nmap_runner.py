from types import SimpleNamespace

import pytest

from nmap_gui import nmap_runner
from nmap_gui.models import ScanMode


ICMP_XML = """
<nmaprun>
  <host>
    <status state="up" reason="echo-reply" />
  </host>
</nmaprun>
""".strip()

PORT_XML = """
<nmaprun>
  <host>
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


def test_parse_icmp_alive_detects_up_host():
    assert nmap_runner.parse_icmp_alive(ICMP_XML) is True


def test_parse_open_ports_returns_sorted_unique_list():
    assert nmap_runner.parse_open_ports(PORT_XML) == [22, 80]


def test_parse_os_guess_reads_name_and_accuracy():
    assert nmap_runner.parse_os_guess(OS_XML) == ("Windows 10", 98)


def test_parse_os_guess_defaults_when_missing():
    assert nmap_runner.parse_os_guess(OS_XML_UNKNOWN) == ("Unknown", None)


def test_run_nmap_raises_on_nonzero_exit(monkeypatch):
    calls = {"run": 0}

    def fake_run(*args, **kwargs):  # noqa: ANN001, ANN202 - pytest helper
        calls["run"] += 1
        return SimpleNamespace(returncode=1, stdout="", stderr="permission denied")

    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "run", fake_run)

    with pytest.raises(nmap_runner.NmapExecutionError):
        nmap_runner.run_nmap(["nmap", "-sS", "127.0.0.1"])
    assert calls["run"] == 1


def test_run_full_scan_converts_parse_errors_to_rf004(monkeypatch):
    def fake_run_nmap(*args, **kwargs):  # noqa: ANN001, ANN202 - pytest helper
        return "this is not xml"

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)
    result = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.ICMP})
    assert result.errors
    assert result.errors[0].code == "RF004"


def test_run_full_scan_falls_back_to_tcp_connect_when_syn_requires_root(monkeypatch):
    calls = []

    def fake_run_nmap(args, timeout=nmap_runner.DEFAULT_TIMEOUT):  # noqa: ANN001, ANN202 - pytest helper
        calls.append(args)
        if "-sS" in args:
            raise nmap_runner.NmapExecutionError(
                "You requested a scan type which requires root privileges"
            )
        return PORT_XML

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)

    result = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.PORTS})

    assert not result.errors
    assert result.open_ports == [22, 80]
    assert any("-sT" in call for call in calls)
