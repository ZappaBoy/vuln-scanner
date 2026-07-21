import json

from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput, ScanResult
from vuln_scanner.tools.abstract import AbstractTool, OUTPUT_FILE_SENTINEL


class Enum4linuxTool(AbstractTool):
    name: str = "enum4linux-ng"
    binary: str = "enum4linux-ng"
    category: str = "network"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.HOST, TargetType.IP})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        host = target.replace("http://", "").replace("https://", "").split("/")[0]

        if scan_input.mode in (ScanMode.PARANOID, ScanMode.PASSIVE):
            flags = ["-A"]          # all, but no brute-force
        elif scan_input.mode == ScanMode.ACTIVE:
            flags = ["-A", "-u", "", "-p", ""]
        else:
            flags = ["-A", "-R"]    # aggressive: include RID cycling

        cmd = ["enum4linux-ng"] + flags + ["-oJ", OUTPUT_FILE_SENTINEL, host]
        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []

        # OS / version info
        os_info = data.get("os_info") or {}
        if os_info:
            os_str = os_info.get("os", os_info.get("lanman_os", ""))
            if os_str:
                findings.append(Finding(
                    title=f"SMB OS: {os_str}",
                    severity=Severity.INFO,
                    description=f"OS detected via SMB: {os_str}",
                    tool=self.name,
                    target=target,
                    raw=os_info,
                ))

        # Shares
        shares = data.get("shares") or {}
        for share_name, share_info in shares.items():
            access = share_info.get("access", "")
            comment = share_info.get("comment", "")
            sev = Severity.MEDIUM if access in ("READ", "READ, WRITE", "READ,WRITE") else Severity.INFO
            findings.append(Finding(
                title=f"SMB share: {share_name} ({access})",
                severity=sev,
                description=(
                    f"Share '{share_name}' on {target}: access={access}"
                    + (f", comment={comment}" if comment else "")
                ),
                tool=self.name,
                target=target,
                raw={"share": share_name, **share_info},
            ))

        # Users
        users = data.get("users") or {}
        for uid, uinfo in users.items():
            username = uinfo.get("username", uid)
            findings.append(Finding(
                title=f"SMB user: {username} (RID {uid})",
                severity=Severity.INFO,
                description=f"Enumerated SMB/Windows user: {username} (RID {uid})",
                tool=self.name,
                target=target,
                raw={"rid": uid, **uinfo},
            ))

        # Groups
        groups = data.get("groups") or {}
        for gid, ginfo in groups.items():
            groupname = ginfo.get("groupname", gid)
            findings.append(Finding(
                title=f"SMB group: {groupname} (RID {gid})",
                severity=Severity.INFO,
                description=f"Enumerated SMB/Windows group: {groupname} (RID {gid})",
                tool=self.name,
                target=target,
                raw={"rid": gid, **ginfo},
            ))

        # Password policy
        ppol = data.get("password_policy") or {}
        if ppol:
            min_len = ppol.get("minimum_password_length", 0)
            lockout = ppol.get("account_lockout_threshold", 0)
            sev = Severity.HIGH if (min_len < 8 or lockout == 0) else Severity.INFO
            findings.append(Finding(
                title=f"SMB password policy: min_len={min_len}, lockout={lockout}",
                severity=sev,
                description=(
                    f"Password policy: minimum length={min_len}, "
                    f"lockout threshold={lockout} (0 means no lockout)."
                ),
                tool=self.name,
                target=target,
                raw=ppol,
            ))

        return findings

    def run(self, target: str, scan_input: ScanInput) -> ScanResult:
        return self._run_with_tempfile(target, scan_input, suffix=".json")
