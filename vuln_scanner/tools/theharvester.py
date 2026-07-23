import json
import os
import subprocess
import tempfile
import time

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import ScanMode, ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult

_SOURCES: dict[ScanMode, str] = {
    ScanMode.PARANOID: "bing",
    ScanMode.PASSIVE: "bing,google,yahoo,sublist3r",
    ScanMode.ACTIVE: "bing,google,yahoo,sublist3r,crtsh,dnsdumpster,hackertarget",
    ScanMode.AGGRESSIVE: "all",
}

_LIMIT: dict[ScanMode, int] = {
    ScanMode.PARANOID: 100,
    ScanMode.PASSIVE: 300,
    ScanMode.ACTIVE: 500,
    ScanMode.AGGRESSIVE: 1000,
}


class TheHarvesterTool(AbstractTool):
    name: str = "theharvester"
    binary: str = "theHarvester"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        # placeholder — overridden by run()
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []

        for email in data.get("emails", []):
            findings.append(
                Finding(
                    title=f"Email: {email}",
                    severity=Severity.INFO,
                    description=f"Email address harvested for {target}: {email}",
                    tool=self.name,
                    target=target,
                    raw={"email": email},
                )
            )

        for host in data.get("hosts", []):
            ip = host.get("ip", "") if isinstance(host, dict) else ""
            hostname = host.get("hostname", host) if isinstance(host, dict) else host
            findings.append(
                Finding(
                    title=f"Host: {hostname}" + (f" ({ip})" if ip else ""),
                    severity=Severity.INFO,
                    description=f"Host discovered for {target}: {hostname}" + (f" → {ip}" if ip else ""),
                    tool=self.name,
                    target=target,
                    raw={"hostname": hostname, "ip": ip},
                )
            )

        for ip in data.get("ips", []):
            findings.append(
                Finding(
                    title=f"IP: {ip}",
                    severity=Severity.INFO,
                    description=f"IP address discovered for {target}: {ip}",
                    tool=self.name,
                    target=target,
                    raw={"ip": ip},
                )
            )

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        sources = _SOURCES[scan_input.mode]
        limit = _LIMIT[scan_input.mode]

        fd, outfile = tempfile.mkstemp(prefix="vs_theharvester_", suffix="")
        os.close(fd)
        # theHarvester appends .json automatically
        outfile_base = outfile

        cmd = [
            "theHarvester",
            "-d",
            domain,
            "-l",
            str(limit),
            "-b",
            sources,
            "-f",
            outfile_base,
        ]
        cmd += scan_input.extra_args

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_input.timeout,
            )
            duration = time.monotonic() - start

            # theHarvester creates <outfile>.json
            json_path = outfile_base + ".json"
            raw = ""
            if os.path.exists(json_path):
                with open(json_path, encoding="utf-8", errors="replace") as f:
                    raw = f.read()
                os.unlink(json_path)

            try:
                os.unlink(outfile_base)
            except FileNotFoundError:
                pass

            findings = self.parse_output(raw, domain)
            return ScanResult(
                tool=self.name,
                target=domain,
                findings=findings,
                duration=duration,
                status=ScanStatus.SUCCESS,
                raw_output=proc.stdout + proc.stderr,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                tool=self.name,
                target=domain,
                duration=float(scan_input.timeout),
                status=ScanStatus.TIMEOUT,
                error=f"Timed out after {scan_input.timeout}s",
            )
        except FileNotFoundError:
            return ScanResult(
                tool=self.name, target=domain, status=ScanStatus.FAILED, error="Binary not found: theHarvester"
            )
        finally:
            for path in (outfile_base, outfile_base + ".json", outfile_base + ".xml"):
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
