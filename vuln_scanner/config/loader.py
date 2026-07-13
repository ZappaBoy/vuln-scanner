import argparse
import tomllib
from argparse import Namespace
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict

from vuln_scanner.config.models import AppConfig, ReportFormat, ScanMode


class _EnvSettings(BaseSettings):
    """Reads VS_* environment variables as a flat override layer."""

    model_config = SettingsConfigDict(env_prefix="VS_", env_ignore_empty=True)

    targets: list[str] | None = None
    timeout: int | None = None
    max_concurrent: int | None = None
    mode: str | None = None
    include_categories: list[str] | None = None
    exclude_categories: list[str] | None = None
    include_tools: list[str] | None = None
    exclude_tools: list[str] | None = None
    report_format: str | None = None
    output_dir: str | None = None
    defectdojo_url: str | None = None
    defectdojo_api_key: str | None = None
    defectdojo_product: str | None = None
    defectdojo_engagement: str | None = None


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="Automated vulnerability assessment scanner and report generator.",
    )
    parser.add_argument(
        "--config", metavar="FILE", help="Path to a TOML config file."
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        metavar="TARGET",
        help="IPs, CIDR ranges, or hostnames to scan. (env: VS_TARGETS)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        metavar="SECONDS",
        help="Per-tool execution timeout in seconds. (env: VS_TIMEOUT)",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        metavar="N",
        help="Max tools running concurrently. (env: VS_MAX_CONCURRENT)",
    )
    parser.add_argument(
        "--mode",
        choices=[m.value for m in ScanMode],
        default=None,
        help=(
            "Scan aggressiveness mode. "
            "paranoid=max stealth, passive=no active probing (default), "
            "active=standard scan, aggressive=full scan. (env: VS_MODE)"
        ),
    )
    parser.add_argument(
        "--include-categories",
        nargs="+",
        metavar="CATEGORY",
        help="Run only these scan categories. (env: VS_INCLUDE_CATEGORIES)",
    )
    parser.add_argument(
        "--exclude-categories",
        nargs="+",
        metavar="CATEGORY",
        help="Skip these scan categories. (env: VS_EXCLUDE_CATEGORIES)",
    )
    parser.add_argument(
        "--include-tools",
        nargs="+",
        metavar="TOOL",
        help="Run only these tools by name. (env: VS_INCLUDE_TOOLS)",
    )
    parser.add_argument(
        "--exclude-tools",
        nargs="+",
        metavar="TOOL",
        help="Skip these tools by name. (env: VS_EXCLUDE_TOOLS)",
    )
    parser.add_argument(
        "--format",
        choices=[f.value for f in ReportFormat],
        default=None,
        metavar="FORMAT",
        help="Report output format (default: markdown). (env: VS_REPORT_FORMAT)",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Directory where reports are written. (env: VS_OUTPUT_DIR)",
    )
    parser.add_argument(
        "--defectdojo-url",
        metavar="URL",
        help="DefectDojo base URL. (env: VS_DEFECTDOJO_URL)",
    )
    parser.add_argument(
        "--defectdojo-api-key",
        metavar="KEY",
        help="DefectDojo API key. (env: VS_DEFECTDOJO_API_KEY)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser


def _load_toml(path: Path) -> dict[str, Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


def load_config(args: Namespace) -> AppConfig:
    """Build AppConfig by merging sources: TOML < env vars < CLI args."""

    # --- layer 1: TOML file (lowest priority) ---
    toml_data: dict[str, Any] = {}
    config_path = Path(args.config) if args.config else Path("config.toml")
    if config_path.exists():
        toml_data = _load_toml(config_path)

    # --- layer 2: env vars ---
    env = _EnvSettings()  # type: ignore[call-arg]

    # --- build merged dict starting from TOML ---
    data = toml_data.copy()
    data.setdefault("scan", {})
    data.setdefault("categories", {})
    data.setdefault("tools", {})
    data.setdefault("report", {})
    data.setdefault("defectdojo", {})

    # apply env vars
    if env.targets is not None:
        data["scan"]["targets"] = env.targets
    if env.timeout is not None:
        data["scan"]["timeout"] = env.timeout
    if env.max_concurrent is not None:
        data["scan"]["max_concurrent"] = env.max_concurrent
    if env.mode is not None:
        data["scan"]["mode"] = env.mode
    if env.include_categories is not None:
        data["categories"]["include"] = env.include_categories
    if env.exclude_categories is not None:
        data["categories"]["exclude"] = env.exclude_categories
    if env.include_tools is not None:
        data["tools"]["include"] = env.include_tools
    if env.exclude_tools is not None:
        data["tools"]["exclude"] = env.exclude_tools
    if env.report_format is not None:
        data["report"]["format"] = env.report_format
    if env.output_dir is not None:
        data["report"]["output_dir"] = env.output_dir
    if env.defectdojo_url is not None:
        data["defectdojo"]["url"] = env.defectdojo_url
    if env.defectdojo_api_key is not None:
        data["defectdojo"]["api_key"] = env.defectdojo_api_key
    if env.defectdojo_product is not None:
        data["defectdojo"]["product_name"] = env.defectdojo_product
    if env.defectdojo_engagement is not None:
        data["defectdojo"]["engagement_name"] = env.defectdojo_engagement

    # --- layer 3: CLI args (highest priority) ---
    if args.targets:
        data["scan"]["targets"] = args.targets
    if args.timeout is not None:
        data["scan"]["timeout"] = args.timeout
    if args.max_concurrent is not None:
        data["scan"]["max_concurrent"] = args.max_concurrent
    if args.mode is not None:
        data["scan"]["mode"] = args.mode
    if args.include_categories:
        data["categories"]["include"] = args.include_categories
    if args.exclude_categories:
        data["categories"]["exclude"] = args.exclude_categories
    if args.include_tools:
        data["tools"]["include"] = args.include_tools
    if args.exclude_tools:
        data["tools"]["exclude"] = args.exclude_tools
    if args.format:
        data["report"]["format"] = args.format
    if args.output_dir:
        data["report"]["output_dir"] = args.output_dir
    if args.defectdojo_url:
        data["defectdojo"]["url"] = args.defectdojo_url
    if args.defectdojo_api_key:
        data["defectdojo"]["api_key"] = args.defectdojo_api_key

    return AppConfig.model_validate(data)
