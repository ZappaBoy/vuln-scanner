

from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vuln_scanner.llm.models import LLMConfig

from pydantic import BaseModel, Field


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


class CategoriesConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class ToolsConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class ReportConfig(BaseModel):
    formats: list[ReportFormat] = Field(default_factory=lambda: [ReportFormat.MARKDOWN])
    output_dir: Path = Path("./reports")

    @classmethod
    def model_validate(cls, data: Any, **kwargs: Any) -> "ReportConfig":
        # Accept legacy single-format string/enum as formats list
        if isinstance(data, dict) and "format" in data and "formats" not in data:
            data = {**data, "formats": [data.pop("format")]}
        return super().model_validate(data, **kwargs)


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
    categories: CategoriesConfig = Field(default_factory=CategoriesConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    defectdojo: DefectDojoConfig = Field(default_factory=DefectDojoConfig)
    llm: AppLLMConfig = Field(default_factory=AppLLMConfig)

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
