from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"


class ScanMode(str, Enum):
    PARANOID = "paranoid"      # maximum stealth, T0 timing, avoids IDS detection
    PASSIVE = "passive"        # no active probing, banner grabbing / enumeration only
    ACTIVE = "active"          # standard port+service scan with vuln checks
    AGGRESSIVE = "aggressive"  # full scan: OS detection, all templates, fast timing


class ScanConfig(BaseModel):
    targets: list[str] = Field(default_factory=list)
    timeout: int = 300
    max_concurrent: int = 3
    mode: ScanMode = ScanMode.PASSIVE
    rate_limit: int | None = None  # requests per second; None = no limit


class CategoriesConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class ToolsConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class ReportConfig(BaseModel):
    format: ReportFormat = ReportFormat.MARKDOWN
    output_dir: Path = Path("./reports")


class DefectDojoConfig(BaseModel):
    url: str = "http://localhost:8080"
    api_key: str = ""
    product_name: str = ""
    engagement_name: str = "Automated Scan"


class AppConfig(BaseModel):
    scan: ScanConfig = Field(default_factory=ScanConfig)
    categories: CategoriesConfig = Field(default_factory=CategoriesConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    defectdojo: DefectDojoConfig = Field(default_factory=DefectDojoConfig)
