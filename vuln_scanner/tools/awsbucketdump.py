"""AWSBucketDump — enumerate S3 buckets for sensitive content."""

import re

from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

_FOUND_RE = re.compile(r"Found interesting file[:\s]+(.+)", re.IGNORECASE)
_BUCKET_RE = re.compile(r"Bucket[:\s]+([^\s\n]+)", re.IGNORECASE)
_INTERSTING = re.compile(
    r"(?:backup|password|secret|key|credentials|config|\.pem|\.key|\.env|dump|export|database)",
    re.IGNORECASE,
)


class AWSBucketDumpTool(AbstractTool):
    name: str = "awsbucketdump"
    binary: str = "python3"
    category: str = "iac"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.CLOUD})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["python3", "/opt/AWSBucketDump/AWSBucketDump.py", "-l", target, "-g", "interesting_Keywords.txt"]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            m = _FOUND_RE.search(line) or (_INTERSTING.search(line) and line.strip())
            if not m:
                continue
            fname = m.group(1).strip() if hasattr(m, "group") else line.strip()
            sev = Severity.HIGH if _INTERSTING.search(fname) else Severity.MEDIUM
            findings.append(
                Finding(
                    title=f"Sensitive S3 file: {fname[:80]}",
                    severity=sev,
                    description=f"AWSBucketDump found: {fname}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-200"],
                    raw={"file": fname},
                )
            )
        return findings
