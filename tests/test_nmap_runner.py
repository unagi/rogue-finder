from nmap_gui import nmap_runner


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
