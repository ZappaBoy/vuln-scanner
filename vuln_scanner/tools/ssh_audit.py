import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput
from vuln_scanner.tools.abstract import AbstractTool


class SSHAuditTool(AbstractTool):
    name: str = "ssh-audit"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("http://", "").replace("https://", "")
        cmd = ["ssh-audit", "-j"]

        if scan_input.mode == ScanMode.PARANOID:
            cmd += ["-T", "5"]          # shorter connect timeout, less footprint

        cmd += scan_input.extra_args
        cmd.append(host)
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        host = data.get("target", target)

        _sev_map = {"critical": Severity.CRITICAL, "warning": Severity.MEDIUM}

        recs = data.get("recommendations") or {}
        for level, categories in recs.items():
            severity = _sev_map.get(level, Severity.LOW)
            for action, algo_groups in categories.items():
                for algo_type, algos in algo_groups.items():
                    for algo in algos:
                        name = algo if isinstance(algo, str) else algo.get("name", str(algo))
                        findings.append(Finding(
                            title=f"SSH: {action} {algo_type} — {name}",
                            severity=severity,
                            description=(
                                f"Recommendation: {action} {algo_type} algorithm '{name}'. "
                                f"Severity: {level}."
                            ),
                            tool=self.name,
                            target=host,
                            raw={"level": level, "action": action, "algo_type": algo_type, "name": name},
                        ))

        # Banner info
        banner = data.get("banner") or {}
        if banner:
            raw_banner = banner.get("raw", "")
            findings.append(Finding(
                title=f"SSH Banner: {raw_banner[:80]}",
                severity=Severity.INFO,
                description=f"SSH server banner: {raw_banner}",
                tool=self.name,
                target=host,
                raw=banner,
            ))

        return findings
