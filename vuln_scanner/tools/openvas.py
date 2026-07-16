"""
OpenVAS / Greenbone Vulnerability Manager integration via gvm-cli.

Requires a running GVM daemon and gvm-cli installed.
Configure connection via environment variables:
  VS_OPENVAS_SOCKET  (default: /var/run/gvm/gvmd.sock)
  VS_OPENVAS_USER    (default: admin)
  VS_OPENVAS_PASS    (default: admin)
"""
import os
import subprocess
import time
import xml.etree.ElementTree as ET

from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

# GVM built-in scan config UUIDs (Greenbone Community Edition defaults)
_CONFIG_IDS: dict[ScanMode, str] = {
    ScanMode.PARANOID:   "2d3f051c-55ba-11e3-bf43-406186ea4fc5",  # Host Discovery
    ScanMode.PASSIVE:    "2d3f051c-55ba-11e3-bf43-406186ea4fc5",  # Host Discovery
    ScanMode.ACTIVE:     "daba56c8-73ec-11df-a475-002264764cea",  # Full and fast
    ScanMode.AGGRESSIVE: "698f691e-7489-11df-9d8c-002264764cea",  # Full and very deep
}

_DEFAULT_PORT_LIST = "730ef368-57e2-11e1-a90f-406186ea4fc5"  # All IANA assigned TCP and UDP


def _gvm(socket: str, user: str, password: str, xml: str, timeout: int = 60) -> str:
    cmd = [
        "gvm-cli", "--gmp-username", user, "--gmp-password", password,
        "socket", "--socketpath", socket, "--xml", xml,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout


class OpenVASTool(AbstractTool):
    name: str = "openvas"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP, TargetType.CIDR})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []  # GVM protocol handled in run()

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        return []  # parsing done inline in run()

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        import logging
        log = logging.getLogger(__name__)
        start = time.monotonic()

        socket = os.environ.get("VS_OPENVAS_SOCKET", "/var/run/gvm/gvmd.sock")
        user   = os.environ.get("VS_OPENVAS_USER", "admin")
        passwd = os.environ.get("VS_OPENVAS_PASS", "admin")

        if not os.path.exists(socket):
            return ScanResult(
                tool=self.name, target=target, duration=0.0,
                status=ScanStatus.SKIPPED,
                error=f"GVM socket not found at {socket}. Is OpenVAS running?",
            )

        try:
            host = target.replace("http://", "").replace("https://", "").split("/")[0]

            # 1. Create target
            xml_create_target = (
                f"<create_target><name>vuln-scanner-{host}</name>"
                f"<hosts>{host}</hosts>"
                f"<port_list id='{_DEFAULT_PORT_LIST}'/>"
                f"</create_target>"
            )
            out = _gvm(socket, user, passwd, xml_create_target)
            target_id = ET.fromstring(out).get("id", "")
            if not target_id:
                return ScanResult(
                    tool=self.name, target=target,
                    duration=time.monotonic() - start,
                    status=ScanStatus.FAILED,
                    error=f"Failed to create GVM target: {out[:200]}",
                )

            # 2. Create task
            config_id = _CONFIG_IDS.get(scan_input.mode, _CONFIG_IDS[ScanMode.ACTIVE])
            xml_create_task = (
                f"<create_task><name>vuln-scanner-{host}</name>"
                f"<config id='{config_id}'/>"
                f"<target id='{target_id}'/>"
                f"</create_task>"
            )
            out = _gvm(socket, user, passwd, xml_create_task)
            task_id = ET.fromstring(out).get("id", "")
            if not task_id:
                return ScanResult(
                    tool=self.name, target=target,
                    duration=time.monotonic() - start,
                    status=ScanStatus.FAILED,
                    error=f"Failed to create GVM task: {out[:200]}",
                )

            # 3. Start task
            _gvm(socket, user, passwd, f"<start_task task_id='{task_id}'/>")
            log.info("[openvas] Task %s started for %s", task_id, target)

            # 4. Poll until done
            deadline = time.monotonic() + scan_input.timeout
            report_id = ""
            while time.monotonic() < deadline:
                out = _gvm(socket, user, passwd, f"<get_tasks task_id='{task_id}'/>")
                root = ET.fromstring(out)
                task_el = root.find("task")
                if task_el is None:
                    break
                status = (task_el.findtext("status") or "").lower()
                log.debug("[openvas] Task status: %s", status)
                if status == "done":
                    last_report = task_el.find("last_report/report")
                    if last_report is not None:
                        report_id = last_report.get("id", "")
                    break
                if status in ("stop requested", "stopped", "interrupted"):
                    break
                time.sleep(20)

            # 5. Fetch report
            findings: list[Finding] = []
            if report_id:
                out = _gvm(socket, user, passwd,
                           f"<get_reports report_id='{report_id}' filter='levels=hmlg'/>")
                findings = self._parse_report_xml(out, target)

            # 6. Cleanup
            _gvm(socket, user, passwd, f"<delete_task task_id='{task_id}' ultimate='false'/>")
            _gvm(socket, user, passwd, f"<delete_target target_id='{target_id}' ultimate='false'/>")

            return ScanResult(
                tool=self.name, target=target, findings=findings,
                duration=time.monotonic() - start, status=ScanStatus.SUCCESS,
            )

        except subprocess.TimeoutExpired:
            return ScanResult(
                tool=self.name, target=target,
                duration=float(scan_input.timeout),
                status=ScanStatus.TIMEOUT,
                error=f"Timed out after {scan_input.timeout}s",
            )
        except FileNotFoundError:
            return ScanResult(
                tool=self.name, target=target, duration=0.0,
                status=ScanStatus.FAILED, error="gvm-cli binary not found.",
            )
        except Exception as exc:  # noqa: BLE001
            return ScanResult(
                tool=self.name, target=target,
                duration=time.monotonic() - start,
                status=ScanStatus.FAILED, error=str(exc),
            )

    def _parse_report_xml(self, xml_str: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return findings

        _sev_map = {
            "high": Severity.HIGH, "medium": Severity.MEDIUM,
            "low": Severity.LOW, "log": Severity.INFO,
        }

        for result in root.iter("result"):
            name = result.findtext("name") or "OpenVAS finding"
            threat = (result.findtext("threat") or "log").lower()
            severity = _sev_map.get(threat, Severity.INFO)
            host_el = result.find("host")
            host = (host_el.text or target) if host_el is not None else target
            port = result.findtext("port") or ""
            desc = result.findtext("description") or ""
            nvt = result.find("nvt") or {}
            cves = [c.text for c in (nvt.findall("cve") if hasattr(nvt, "findall") else [])
                    if c.text and c.text.startswith("CVE-")]
            refs = [r.text for r in (nvt.findall("refs/ref") if hasattr(nvt, "findall") else [])
                    if r.text]
            findings.append(Finding(
                title=name + (f" ({port})" if port else ""),
                severity=severity,
                description=desc,
                tool=self.name,
                target=host,
                cve=cves,
                references=refs,
                raw={"threat": threat, "port": port},
            ))
        return findings
