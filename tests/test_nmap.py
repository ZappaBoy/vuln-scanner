from vuln_scanner.tools.enums import ScanMode, Severity
from vuln_scanner.tools.models import ScanInput
from vuln_scanner.tools.nmap import NmapTool

_XML_TWO_PORTS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

_XML_NO_OPEN_PORTS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="9999">
        <state state="filtered"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def _tool() -> NmapTool:
    return NmapTool()


def test_parse_two_open_ports():
    findings = _tool().parse_output(_XML_TWO_PORTS, "10.0.0.1")
    assert len(findings) == 2
    titles = {f.title for f in findings}
    assert any("22/tcp" in t for t in titles)
    assert any("80/tcp" in t for t in titles)


def test_parse_closed_ports_excluded():
    findings = _tool().parse_output(_XML_TWO_PORTS, "10.0.0.1")
    assert all("443" not in f.title for f in findings)


def test_parse_no_open_ports():
    findings = _tool().parse_output(_XML_NO_OPEN_PORTS, "10.0.0.2")
    assert findings == []


def test_parse_empty_output():
    findings = _tool().parse_output("", "10.0.0.1")
    assert findings == []


def test_parse_invalid_xml():
    findings = _tool().parse_output("not xml at all", "10.0.0.1")
    assert findings == []


def test_findings_severity_is_info():
    findings = _tool().parse_output(_XML_TWO_PORTS, "10.0.0.1")
    assert all(f.severity == Severity.INFO for f in findings)


def test_findings_tool_name():
    findings = _tool().parse_output(_XML_TWO_PORTS, "10.0.0.1")
    assert all(f.tool == "nmap" for f in findings)


def test_service_product_in_description():
    findings = _tool().parse_output(_XML_TWO_PORTS, "10.0.0.1")
    ssh = next(f for f in findings if "22" in f.title)
    assert "OpenSSH" in ssh.title


def test_build_command_passive_mode():
    scan_input = ScanInput(targets=["10.0.0.1"], mode=ScanMode.PASSIVE)
    cmd = _tool().build_command("10.0.0.1", scan_input)
    assert "-sn" in cmd
    assert "-T1" in cmd


def test_build_command_aggressive_mode():
    scan_input = ScanInput(targets=["10.0.0.1"], mode=ScanMode.AGGRESSIVE)
    cmd = _tool().build_command("10.0.0.1", scan_input)
    assert "-A" in cmd
    assert "-T4" in cmd


def test_build_command_active_mode():
    scan_input = ScanInput(targets=["10.0.0.1"], mode=ScanMode.ACTIVE)
    cmd = _tool().build_command("10.0.0.1", scan_input)
    assert "-sV" in cmd
    assert "-T3" in cmd


def test_build_command_extra_args():
    scan_input = ScanInput(targets=["10.0.0.1"], mode=ScanMode.ACTIVE, extra_args=["--top-ports", "100"])
    cmd = _tool().build_command("10.0.0.1", scan_input)
    assert "--top-ports" in cmd
    assert "100" in cmd
