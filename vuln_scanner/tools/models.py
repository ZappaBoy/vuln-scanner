"""Pydantic data models: Finding, ScanInput, ScanResult, AuthConfig."""
from pydantic import BaseModel, Field

from vuln_scanner.tools.enums import Confidence, ScanMode, ScanStatus, Severity


class AuthConfig(BaseModel):
    """Credentials for authenticated scanning.

    Global defaults live at [scan.auth]; per-target overrides live under
    [scan.auth.targets."<target>"] and take full precedence for that target.
    Call ``for_target(target)`` to get the resolved config for a specific target.
    """
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    bearer_token: str = ""
    username: str = ""
    password: str = ""
    login_url: str = ""
    login_data: dict[str, str] = Field(default_factory=dict)
    verify_ssl: bool = True
    # Per-target overrides keyed by exact target string.
    # A matching entry completely replaces the global config for that target.
    targets: dict[str, "AuthConfig"] = Field(default_factory=dict)

    def for_target(self, target: str) -> "AuthConfig":
        """Return the auth config to use for *target*.

        If a per-target entry exists it is returned as-is (it already carries
        its own cookies/headers/etc.).  Otherwise the global config (self,
        minus the ``targets`` dict) is returned.
        """
        if target in self.targets:
            return self.targets[target]
        return self

    @property
    def cookie_string(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    @property
    def effective_headers(self) -> dict[str, str]:
        h = dict(self.headers)
        if self.bearer_token and "Authorization" not in h:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        if self.cookies and "Cookie" not in h:
            h["Cookie"] = self.cookie_string
        return h

    @property
    def is_configured(self) -> bool:
        return bool(
            self.cookies or self.headers or self.bearer_token
            or self.username or self.login_url
        )


class Finding(BaseModel):
    title: str
    severity: Severity
    description: str
    tool: str
    target: str
    cve: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)

    # Evidence: raw HTTP request/response that triggered the finding
    request: str = ""
    response: str = ""

    # LLM-enriched fields (all optional/defaulted for backward compatibility)
    cwe: list[str] = Field(default_factory=list)
    mitigation: str = ""
    remediation: str = ""
    confidence: Confidence = Confidence.UNKNOWN
    false_positive: bool | None = None
    cluster_id: str | None = None
    llm_notes: str = ""
    exploitability: str = ""
    poc_ids: list[str] = Field(default_factory=list)

    # CVSS v3.1
    cvss_vector: str = ""          # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cvss_score: float | None = None


class ScanInput(BaseModel):
    targets: list[str]
    timeout: int = 300
    mode: ScanMode = ScanMode.PASSIVE
    rate_limit: int | None = None
    extra_args: list[str] = Field(default_factory=list)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    proxy: str | None = None   # e.g. "http://127.0.0.1:8080"


class ScanResult(BaseModel):
    tool: str
    target: str
    findings: list[Finding] = Field(default_factory=list)
    duration: float = 0.0
    status: ScanStatus = ScanStatus.SUCCESS
    error: str | None = None
    raw_output: str = ""
