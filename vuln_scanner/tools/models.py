"""Pydantic data models: Finding, ScanInput, ScanResult, AuthConfig."""
from pydantic import BaseModel, Field

from vuln_scanner.tools.enums import Confidence, ScanMode, ScanStatus, Severity


class AuthConfig(BaseModel):
    """Credentials carried with every scan task for authenticated scanning."""
    # HTTP cookies forwarded verbatim (name → value)
    cookies: dict[str, str] = Field(default_factory=dict)
    # Extra request headers, e.g. {"Authorization": "Bearer <token>"}
    headers: dict[str, str] = Field(default_factory=dict)
    # Convenience shorthand for Authorization: Bearer <token>
    bearer_token: str = ""
    # HTTP Basic / Digest credentials
    username: str = ""
    password: str = ""
    # Form-based login: POST login_url with login_data to obtain a session
    login_url: str = ""
    login_data: dict[str, str] = Field(default_factory=dict)
    verify_ssl: bool = True

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


class ScanInput(BaseModel):
    targets: list[str]
    timeout: int = 300
    mode: ScanMode = ScanMode.PASSIVE
    rate_limit: int | None = None
    extra_args: list[str] = Field(default_factory=list)
    auth: AuthConfig = Field(default_factory=AuthConfig)


class ScanResult(BaseModel):
    tool: str
    target: str
    findings: list[Finding] = Field(default_factory=list)
    duration: float = 0.0
    status: ScanStatus = ScanStatus.SUCCESS
    error: str | None = None
    raw_output: str = ""
