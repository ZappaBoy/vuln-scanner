"""Data models for generated PoC scripts and execution results."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PocVerdict(str, Enum):
    CONFIRMED = "confirmed"  # PoC ran and output matched expected indicator
    INCONCLUSIVE = "inconclusive"  # PoC ran but outcome unclear
    FAILED = "failed"  # PoC script error / non-zero exit
    NOT_RUN = "not_run"  # generation-only; execution skipped or not allowed
    UNSAFE = "unsafe"  # LLM flagged safe_to_run=false; script not executed


class Poc(BaseModel):
    id: str
    finding_keys: list[str] = Field(default_factory=list)  # finding identity refs
    language: str = "python"
    script: str = ""
    description: str = ""
    expected_indicator: str = ""
    safe_to_run: bool = True
    safety_notes: str = ""
    # Source provenance: "llm-generated", "git-clone:<url>", etc.
    provenance: str = "llm-generated"
    # Execution results (populated by runner)
    verdict: PocVerdict = PocVerdict.NOT_RUN
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    # Path to the written script file (relative to assets_dir)
    script_path: str = ""
    # Metadata from LLM response
    raw_llm: dict[str, Any] = Field(default_factory=dict)
