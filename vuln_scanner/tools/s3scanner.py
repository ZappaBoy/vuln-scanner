"""S3Scanner — scan for open and misconfigured AWS S3 buckets."""
import json
import re

from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool

_OPEN_RE = re.compile(r"(?:open|public|accessible|readable|writable)[:\s]+([^\n]+)", re.IGNORECASE)
_BUCKET_RE = re.compile(r"bucket[:\s]+([^\s\n]+)", re.IGNORECASE)


class S3ScannerTool(AbstractTool):
    name: str = "s3scanner"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["s3scanner", "scan", "--bucket", target, "--json"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
            buckets = data if isinstance(data, list) else [data]
            for bucket in buckets:
                name = bucket.get("name", target)
                exists = bucket.get("exists", False)
                if not exists:
                    continue
                public_read = bucket.get("permission_authenticated_users_read", False) or \
                              bucket.get("permission_all_users_read", False)
                public_write = bucket.get("permission_all_users_write", False)
                if public_write:
                    findings.append(Finding(
                        title=f"Public write S3 bucket: {name}",
                        severity=Severity.CRITICAL,
                        description=f"S3 bucket '{name}' allows public write access",
                        tool=self.name, target=target, cwe=["CWE-284"],
                        raw=bucket,
                    ))
                elif public_read:
                    findings.append(Finding(
                        title=f"Public read S3 bucket: {name}",
                        severity=Severity.HIGH,
                        description=f"S3 bucket '{name}' allows public read access",
                        tool=self.name, target=target, cwe=["CWE-284"],
                        raw=bucket,
                    ))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                if _OPEN_RE.search(line):
                    bm = _BUCKET_RE.search(line)
                    bucket = bm.group(1) if bm else target
                    findings.append(Finding(
                        title=f"Open S3 bucket: {bucket}",
                        severity=Severity.HIGH,
                        description=line.strip(),
                        tool=self.name, target=target, cwe=["CWE-284"],
                        raw={"line": line},
                    ))
        return findings
