"""jwt_tool — JWT security testing toolkit (decode, tamper, crack, playbook attacks)."""

import re

from vuln_scanner.tools.abstract import AbstractTool, _as_url
from vuln_scanner.tools.enums import ScanMode, Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

# jwt_tool output markers
_VULN_RE = re.compile(
    r"\[\!\]\s*(?P<msg>.+)",
    re.IGNORECASE,
)
_CRACK_RE = re.compile(r"SECRET KEY FOUND:\s*(?P<secret>.+)", re.IGNORECASE)
_ALG_NONE_RE = re.compile(r"alg.*none.*(?:accepted|success|valid)", re.IGNORECASE)
_JWKS_RE = re.compile(r"JWKS.*(?:inject|spoof|bypass)", re.IGNORECASE)


class JwtToolTool(AbstractTool):
    name: str = "jwt-tool"
    binary: str = "jwt-tool"
    category: str = "web"
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        url = _as_url(target)
        auth = scan_input.auth
        token = auth.bearer_token or ""

        if not token:
            # No token to test — return a no-op command
            return ["true"]

        cmd = [
            "jwt-tool",
            token,
            "-t",
            url,
        ]

        if scan_input.mode in (ScanMode.ACTIVE, ScanMode.AGGRESSIVE):
            # Playbook mode — runs all common attacks
            cmd += ["-M", "pb"]
        else:
            # Just decode and check for weak signing
            cmd += ["-M", "at"]

        # Pass auth headers so jwt_tool sends the token with requests
        for k, v in auth.effective_headers.items():
            cmd += ["-rh", f"{k}: {v}"]

        if scan_input.proxy:
            cmd += ["-pr", scan_input.proxy]

        cmd += scan_input.extra_args
        return cmd

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []

        # Secret cracked
        for m in _CRACK_RE.finditer(raw):
            secret = m.group("secret").strip()
            findings.append(
                Finding(
                    title=f"JWT secret key cracked at {target}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"jwt_tool successfully cracked the JWT signing secret.\n"
                        f"Secret: {secret}\n"
                        f"An attacker can forge arbitrary JWT tokens."
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-321", "CWE-347"],
                    raw={"secret": secret},
                )
            )

        # alg:none accepted
        if _ALG_NONE_RE.search(raw):
            findings.append(
                Finding(
                    title=f"JWT alg:none accepted at {target}",
                    severity=Severity.CRITICAL,
                    description=(
                        "The server accepted a JWT with algorithm set to 'none', "
                        "meaning no signature verification is performed.\n"
                        "An attacker can forge arbitrary tokens without knowing the secret."
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-347"],
                    raw={"attack": "alg_none"},
                )
            )

        # JWKS injection / spoofing
        if _JWKS_RE.search(raw):
            findings.append(
                Finding(
                    title=f"JWT JWKS injection possible at {target}",
                    severity=Severity.HIGH,
                    description=(
                        "jwt_tool found evidence of JWKS URI spoofing or injection vulnerability.\n"
                        "An attacker may be able to supply their own public key to sign tokens."
                    ),
                    tool=self.name,
                    target=target,
                    cwe=["CWE-347"],
                    raw={"attack": "jwks_injection"},
                )
            )

        # Generic [!] vulnerability markers
        seen: set[str] = set()
        for m in _VULN_RE.finditer(raw):
            msg = m.group("msg").strip()
            if any(skip in msg.lower() for skip in ("testing", "checking", "trying")):
                continue
            key = msg[:80]
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    title=f"JWT vulnerability: {msg[:80]}",
                    severity=Severity.HIGH,
                    description=f"jwt_tool flagged: {msg}",
                    tool=self.name,
                    target=target,
                    cwe=["CWE-347"],
                    raw={"message": msg},
                )
            )

        return findings
