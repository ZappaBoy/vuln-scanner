

from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vuln_scanner.llm.models import LLMConfig

from pydantic import BaseModel, Field, field_validator

from vuln_scanner.tools.models import AuthConfig
from vuln_scanner.scope import ScopeConfig


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"


class ScanMode(str, Enum):
    PARANOID = "paranoid"
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"


class ScanConfig(BaseModel):
    targets: list[str] = Field(default_factory=list)
    timeout: int = 300
    max_concurrent: int = 3
    mode: ScanMode = ScanMode.PASSIVE
    rate_limit: int | None = None
    proxy: str | None = None   # e.g. "http://127.0.0.1:8080"


class CategoriesConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class ToolsConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class ReportConfig(BaseModel):
    formats: list[ReportFormat] = Field(default_factory=lambda: [ReportFormat.MARKDOWN])
    output_dir: Path = Path("./reports")
    min_severity: str = "none"  # "none"|"info"|"low"|"medium"|"high"|"critical"

    @classmethod
    def model_validate(cls, data: Any, **kwargs: Any) -> "ReportConfig":
        # Accept legacy single-format string/enum as formats list
        if isinstance(data, dict) and "format" in data and "formats" not in data:
            data = {**data, "formats": [data.pop("format")]}
        return super().model_validate(data, **kwargs)


class PluginsConfig(BaseModel):
    """Plugin auto-discovery configuration."""
    enabled: bool = True
    # Extra directories to scan for plugin .py files (in addition to ./plugins/)
    dirs: list[Path] = Field(default_factory=list)


class NucleiConfig(BaseModel):
    """Fine-grained Nuclei template and execution configuration."""

    # ── Template management ───────────────────────────────────────────────────
    # Path to the nuclei-templates directory.  Default: nuclei's own default
    # (~/.local/nuclei-templates).  Set to override.
    templates_dir: Path | None = None

    # Additional template directories or individual .yaml files to include
    # on top of the main templates_dir.
    custom_templates: list[Path] = Field(default_factory=list)

    # Nuclei community / third-party template repos to pull.
    # Each entry is passed to `nuclei -update-templates -ud <dir>` style or
    # as a GitHub slug "projectdiscovery/nuclei-templates".
    # Listed repos are cloned/updated alongside the official templates.
    community_templates: list[str] = Field(default_factory=list)

    # Run `nuclei -update-templates` before every scan to keep templates fresh.
    update_templates: bool = False

    # Only run templates that were added or modified in the most recent update
    # (`nuclei -new-templates`).  Useful for daily delta scans.
    only_new_templates: bool = False

    # ── Tag / severity filtering (override the per-mode defaults) ─────────────
    # When non-empty these REPLACE the mode-based defaults — they don't merge.
    tags: list[str] = Field(default_factory=list)
    exclude_tags: list[str] = Field(
        default_factory=lambda: ["dos", "fuzz", "intrusive"],
    )

    # Workflow .yaml files to execute (run in addition to template scanning).
    workflows: list[Path] = Field(default_factory=list)

    # ── Performance ───────────────────────────────────────────────────────────
    rate_limit: int = 150          # maximum HTTP requests per second
    bulk_size: int = 25            # number of templates processed per host batch
    concurrency: int = 25          # concurrent template executions
    timeout: int = 5               # per-request timeout (seconds)
    retries: int = 1               # number of retries on request failure

    # ── Headless browser ──────────────────────────────────────────────────────
    headless: bool = False         # enable headless Chrome/Chromium support
    headless_timeout: int = 20     # headless page load timeout (seconds)

    # ── Interactsh (OOB interaction server) ───────────────────────────────────
    no_interactsh: bool = True     # disable by default; enable for active/aggressive
    interactsh_server: str = ""    # custom interactsh server URL
    interactsh_token: str = ""     # authentication token for custom server


class ReconConfig(BaseModel):
    """Asset-discovery pipeline that runs before the main scan.

    When enabled, HOST-type targets (bare domain names) trigger a
    subdomain enumeration → DNS resolution → liveness check pipeline.
    The discovered live URLs are then added to the scan target list
    (after scope validation).
    """

    enabled: bool = True

    # Tools to run at each stage.  Each list is tried in order; the first
    # binary found on PATH is used.  Set to [] to skip that stage entirely.
    enum_tools: list[str] = Field(
        default_factory=lambda: ["subfinder", "amass"],
        description="Subdomain enumeration tools (passive recon).",
    )
    resolve_tools: list[str] = Field(
        default_factory=lambda: ["puredns", "dnsx"],
        description="DNS resolution / wildcard-filtering tools.",
    )
    probe_tools: list[str] = Field(
        default_factory=lambda: ["httpx"],
        description="HTTP liveness probing tools (emit discovered URLs).",
    )

    # Timeout per individual recon tool (seconds).
    timeout: int = 120

    # Validate every discovered asset against [scope] before adding it to targets.
    scope_validate: bool = True


class DefectDojoConfig(BaseModel):
    url: str = "http://localhost:8080"
    api_key: str = ""
    product_name: str = ""
    engagement_name: str = "Automated Scan"


# ─── LLM config (imported here to avoid circular imports) ────────────────────

def _default_llm_config() -> "AppLLMConfig":
    return AppLLMConfig()


class AppLLMConfig(BaseModel):
    """Thin shim that merges into LLMConfig at load time.

    Stored as plain dict-compatible pydantic model so it can be embedded in
    AppConfig without pulling in the openai dependency at import time.
    """
    enabled: Any = "auto"

    @field_validator("enabled", mode="before")
    @classmethod
    def _coerce_enabled(cls, v: Any) -> Any:
        if isinstance(v, str):
            if v.lower() in ("false", "0", "no", "off"):
                return False
            if v.lower() in ("true", "1", "yes", "on"):
                return True
        return v
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    organization: str = ""
    timeout: float = 60.0
    max_retries: int = 2
    extra_headers: dict[str, str] = Field(default_factory=dict)
    extra_query: dict[str, str] = Field(default_factory=dict)
    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None
    frequency_penalty: float | None = None
    presence_penalty: float | None = None
    seed: int | None = None
    stop: list[str] | None = None
    extra_body: dict[str, Any] = Field(default_factory=dict)
    include_tools: list[str] = Field(default_factory=list)
    exclude_tools: list[str] = Field(default_factory=list)
    include_categories: list[str] = Field(default_factory=list)
    exclude_categories: list[str] = Field(default_factory=list)
    # Nested sub-configs stored as raw dicts; converted to proper types in loader
    features: dict[str, Any] = Field(default_factory=dict)
    tool_features: dict[str, Any] = Field(default_factory=dict)
    category_features: dict[str, Any] = Field(default_factory=dict)
    prompts: dict[str, str] = Field(default_factory=dict)
    poc: dict[str, Any] = Field(default_factory=dict)


class AppConfig(BaseModel):
    scan: ScanConfig = Field(default_factory=ScanConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    categories: CategoriesConfig = Field(default_factory=CategoriesConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    defectdojo: DefectDojoConfig = Field(default_factory=DefectDojoConfig)
    llm: AppLLMConfig = Field(default_factory=AppLLMConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)

    def build_llm_config(self) -> "LLMConfig":
        """Convert AppLLMConfig → typed LLMConfig (lazy, avoids circular imports)."""
        from vuln_scanner.llm.models import LLMConfig, LLMFeatures, LLMPrompts, PocConfig

        raw = self.llm.model_dump()

        # Convert nested dicts to proper types
        features_data = raw.pop("features", {})
        tool_features_data = raw.pop("tool_features", {})
        category_features_data = raw.pop("category_features", {})
        prompts_data = raw.pop("prompts", {})
        poc_data = raw.pop("poc", {})

        return LLMConfig(
            **raw,
            features=LLMFeatures(**features_data) if features_data else LLMFeatures(),
            tool_features={
                k: LLMFeatures(**v) for k, v in tool_features_data.items()
            },
            category_features={
                k: LLMFeatures(**v) for k, v in category_features_data.items()
            },
            prompts=LLMPrompts(**prompts_data) if prompts_data else LLMPrompts(),
            poc=PocConfig(**poc_data) if poc_data else PocConfig(),
        )
