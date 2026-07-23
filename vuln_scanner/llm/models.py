"""LLM configuration models — OpenAI-compatible, fully customisable."""

from typing import Any

from pydantic import BaseModel, Field

from vuln_scanner.llm import prompts as _default_prompts
from vuln_scanner.llm.features import LLMFeatures


class LLMPrompts(BaseModel):
    """Overridable prompt templates. Any field left empty uses the built-in default."""

    enrich_system: str = ""
    enrich_user: str = ""
    cluster_system: str = ""
    cluster_user: str = ""
    mitigation_system: str = ""
    mitigation_user: str = ""
    poc_system: str = ""
    poc_user: str = ""

    def get(self, name: str) -> str:
        """Return the configured prompt or fall back to the built-in default."""
        value = getattr(self, name, "")
        if value:
            return value
        return getattr(_default_prompts, name.upper(), "")


class PocConfig(BaseModel):
    """PoC generation/execution mechanics (on/off switches live in LLMFeatures)."""

    languages: list[str] = Field(default_factory=lambda: ["python", "bash"])
    timeout: int = 120
    allow_git_clone: bool = False
    max_pocs: int = 20
    only_severities: list[str] = Field(default_factory=lambda: ["critical", "high", "medium"])
    assets_dir: str = ""  # empty = auto (<report>_assets/poc/)


class LLMConfig(BaseModel):
    """Full OpenAI-compatible LLM configuration."""

    # Connection
    enabled: bool | str = "auto"  # True, False, or "auto" (on iff api_key is set)
    base_url: str = ""  # override for non-OpenAI endpoints (Ollama, vLLM, etc.)
    api_key: str = ""
    model: str = ""  # REQUIRED when LLM is active — validated at runtime
    organization: str = ""
    timeout: float = 60.0
    max_retries: int = 2
    extra_headers: dict[str, str] = Field(default_factory=dict)
    extra_query: dict[str, str] = Field(default_factory=dict)

    # Sampling — all OpenAI-compatible, passed straight through
    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None
    frequency_penalty: float | None = None
    presence_penalty: float | None = None
    seed: int | None = None
    stop: list[str] | None = None
    # Non-standard params (e.g. top_k for Ollama/vLLM) go here as extra_body
    extra_body: dict[str, Any] = Field(default_factory=dict)

    # Minimum severity to analyse — findings below this threshold are skipped.
    # Default "medium" means INFO and LOW findings are not sent to the LLM.
    min_severity: str = "medium"

    # Scope filters (mirror orchestrator include/exclude semantics)
    include_tools: list[str] = Field(default_factory=list)
    exclude_tools: list[str] = Field(default_factory=list)
    include_categories: list[str] = Field(default_factory=list)
    exclude_categories: list[str] = Field(default_factory=list)

    # Feature matrix
    features: LLMFeatures = Field(default_factory=LLMFeatures)
    tool_features: dict[str, LLMFeatures] = Field(default_factory=dict)
    category_features: dict[str, LLMFeatures] = Field(default_factory=dict)

    # Prompt overrides
    prompts: LLMPrompts = Field(default_factory=LLMPrompts)

    # PoC mechanics
    poc: PocConfig = Field(default_factory=PocConfig)

    @property
    def is_active(self) -> bool:
        """True when LLM should actually run."""
        if self.enabled is True:
            return True
        if self.enabled is False:
            return False
        # "auto"
        return bool(self.api_key)

    def validate_active(self) -> None:
        """Raise ValueError if LLM is active but misconfigured."""
        if not self.is_active:
            return
        if not self.model:
            raise ValueError(
                "LLM is active but 'llm.model' is not set. Set VS_LLM_MODEL or [llm] model = \"...\" in config."
            )

    def in_scope(self, tool_name: str, category: str) -> bool:
        """Return True if the LLM should process this tool's results."""
        if self.include_tools and tool_name not in self.include_tools:
            return False
        if tool_name in self.exclude_tools:
            return False
        if self.include_categories and category not in self.include_categories:
            return False
        if category in self.exclude_categories:
            return False
        return True

    def resolve_features(self, tool_name: str, category: str) -> LLMFeatures:
        from vuln_scanner.llm.features import resolve_features

        return resolve_features(
            self.features,
            self.tool_features,
            self.category_features,
            tool_name,
            category,
        )
