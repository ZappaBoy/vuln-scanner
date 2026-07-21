"""massdns — high-performance passive DNS resolver for bulk subdomain recon."""
import os
import re
import subprocess
import tempfile
import time

from vuln_scanner.tools.enums import ScanStatus, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool

_RESOLV_RE = re.compile(r"^(\S+)\.\s+\d+\s+IN\s+A\s+(\S+)$")

_RESOLVERS = "/usr/share/massdns/resolvers.txt"


class MassDNSTool(AbstractTool):
    name: str = "massdns"
    binary: str = "massdns"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return []

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _RESOLV_RE.match(line)
            if m:
                sub, ip = m.group(1).rstrip("."), m.group(2)
                if sub not in seen:
                    seen.add(sub)
                    findings.append(Finding(
                        title=f"Resolved subdomain: {sub} → {ip}",
                        severity=Severity.INFO,
                        description=f"massdns resolved {sub} to {ip}",
                        tool=self.name,
                        target=target,
                        cwe=[],
                        raw={"subdomain": sub, "ip": ip},
                    ))
        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        # massdns needs a wordlist to generate subdomains to resolve
        wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/subdomains.txt"

        fd, domain_file = tempfile.mkstemp(prefix="vs_massdns_", suffix=".txt")
        start = time.monotonic()
        try:
            with os.fdopen(fd, "w") as f:
                try:
                    with open(wordlist) as wf:
                        for word in wf:
                            word = word.strip()
                            if word:
                                f.write(f"{word}.{target}\n")
                except OSError:
                    f.write(f"www.{target}\nmail.{target}\ndev.{target}\nstaging.{target}\n")

            resolvers = _RESOLVERS if os.path.exists(_RESOLVERS) else ""
            cmd = ["massdns", "-r", resolvers, "-t", "A", "-o", "S", domain_file] if resolvers else \
                  ["massdns", "-t", "A", "-o", "S", domain_file]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_input.timeout)
            duration = time.monotonic() - start
            raw = proc.stdout + proc.stderr
            return ScanResult(
                tool=self.name, target=target,
                findings=self.parse_output(raw, target),
                duration=duration, status=ScanStatus.SUCCESS, raw_output=raw,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(tool=self.name, target=target,
                              duration=float(scan_input.timeout), status=ScanStatus.TIMEOUT,
                              error=f"Timed out after {scan_input.timeout}s")
        except FileNotFoundError:
            return ScanResult(tool=self.name, target=target, duration=0.0,
                              status=ScanStatus.FAILED, error="Binary not found: massdns")
        finally:
            try:
                os.unlink(domain_file)
            except OSError:
                pass
