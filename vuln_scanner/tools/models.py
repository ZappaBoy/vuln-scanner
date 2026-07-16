"""Pydantic data models: Finding, ScanInput, ScanResult."""
from pydantic import BaseModel, Field

from vuln_scanner.tools.enums import Confidence, ScanMode, ScanStatus, Severity


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


class ScanResult(BaseModel):
    tool: str
    target: str
    findings: list[Finding] = Field(default_factory=list)
    duration: float = 0.0
    status: ScanStatus = ScanStatus.SUCCESS
    error: str | None = None
    raw_output: str = ""
