"""LLM feature flag matrix with per-tool / per-category override resolution."""


from pydantic import BaseModel


class LLMFeatures(BaseModel):
    """Named boolean feature flags for the LLM analysis pipeline."""
    logs_analysis: bool = True        # feed tool raw_output/error into analysis
    enrich: bool = True               # CWE/confidence/false_positive/exploitability triage
    classify: bool = True             # classify findings (used in clustering pass)
    cluster: bool = True              # group findings into root-cause clusters
    mitigation: bool = True           # generate mitigation + remediation per finding
    generate_poc: bool = True         # generate PoC scripts as report assets
    execute_poc: bool = False         # execute PoCs (container-only, off by default)
    false_positive_filter: bool = True  # suppress likely false positives from report

    def merge(self, override: "LLMFeatures | None") -> "LLMFeatures":
        """Return a new LLMFeatures with any non-None override fields applied."""
        if override is None:
            return self
        data = self.model_dump()
        for k, v in override.model_dump(exclude_unset=True).items():
            data[k] = v
        return LLMFeatures(**data)


def resolve_features(
    global_features: LLMFeatures,
    tool_overrides: dict[str, LLMFeatures],
    category_overrides: dict[str, LLMFeatures],
    tool_name: str,
    category: str,
) -> LLMFeatures:
    """Resolve effective features with precedence: tool > category > global."""
    effective = global_features
    # category wins over global
    if category in category_overrides:
        effective = effective.merge(category_overrides[category])
    # tool wins over category
    if tool_name in tool_overrides:
        effective = effective.merge(tool_overrides[tool_name])
    return effective
