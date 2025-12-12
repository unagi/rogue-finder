import io

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


def test_run_nmap_raises_on_nonzero_exit(monkeypatch):
    class FakeProcess:
        def __init__(self):
            self.returncode = 1
            self.stdout = io.StringIO("")
            self.stderr = io.StringIO("permission denied\n")

        def wait(self, timeout=None):  # noqa: D401 - test helper
            return self.returncode

        def kill(self):
            pass

    created = {"count": 0}

    def fake_popen(*args, **kwargs):  # noqa: ANN001, ANN202 - pytest helper
        created["count"] += 1
        return FakeProcess()

    monkeypatch.setattr(nmap_runner, "ensure_nmap_available", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(nmap_runner.subprocess, "Popen", fake_popen)

    with pytest.raises(nmap_runner.NmapExecutionError):
        nmap_runner.run_nmap(["nmap", "-sS", "127.0.0.1"])
    assert created["count"] == 1


def test_run_full_scan_converts_parse_errors_to_rf004(monkeypatch):
    def fake_run_nmap(*args, **kwargs):  # noqa: ANN001, ANN202 - pytest helper
        return "this is not xml"

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)
    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.ICMP})
    assert results
    assert results[0].errors
    assert results[0].errors[0].code == "RF004"


def test_run_full_scan_falls_back_to_tcp_connect_when_syn_requires_root(monkeypatch):
    calls = []

    def fake_run_nmap(args, timeout=nmap_runner.DEFAULT_TIMEOUT, **kwargs):  # noqa: ANN001, ANN202 - helper
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
        <address addr="192.168.100.11" addrtype="ipv4" />
      </host>
      <host>
        <status state="up" />
        <address addr="192.168.100.13" addrtype="ipv4" />
      </host>
    </nmaprun>
    """.strip()

    port_xml = """
    <nmaprun>
      <host>
        <address addr="192.168.100.11" addrtype="ipv4" />
        <ports>
          <port protocol="tcp" portid="22"><state state="open"/></port>
        </ports>
      </host>
      <host>
        <address addr="192.168.100.13" addrtype="ipv4" />
        <ports>
          <port protocol="tcp" portid="80"><state state="open"/></port>
        </ports>
      </host>
    </nmaprun>
    """.strip()

    os_xml = """
    <nmaprun>
      <host>
        <address addr="192.168.100.11" addrtype="ipv4" />
        <os>
          <osmatch name="Linux" accuracy="90" />
        </os>
      </host>
      <host>
        <address addr="192.168.100.13" addrtype="ipv4" />
        <os>
          <osmatch name="Windows" accuracy="80" />
        </os>
      </host>
    </nmaprun>
    """.strip()

    responses = [icmp_xml, port_xml, os_xml]

    def fake_run_nmap(*args, **kwargs):  # noqa: ANN001, ANN202 - pytest helper
        return responses.pop(0)

    monkeypatch.setattr(nmap_runner, "run_nmap", fake_run_nmap)

    results = nmap_runner.run_full_scan(
        "192.168.100.0/30",
        {ScanMode.ICMP, ScanMode.PORTS, ScanMode.OS},
    )

    assert len(results) == EXPECTED_CIDR_HOSTS
    by_target = {item.target: item for item in results}
    assert by_target["192.168.100.11"].open_ports == [22]
    assert by_target["192.168.100.13"].open_ports == [80]
    if not MAC_WITHOUT_ROOT:
        assert by_target["192.168.100.11"].os_guess == "Linux"
        assert by_target["192.168.100.13"].os_guess == "Windows"


def test_run_full_scan_marks_host_alive_when_only_ports(monkeypatch):
    monkeypatch.setattr(nmap_runner, "run_nmap", lambda *args, **kwargs: PORT_XML)

    results = nmap_runner.run_full_scan("127.0.0.1", {ScanMode.PORTS})

    assert results
    assert results[0].is_alive is True
