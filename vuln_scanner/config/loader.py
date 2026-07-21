

import argparse
import os
import tomllib
from argparse import Namespace
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict

from vuln_scanner.config.models import AppConfig, ReportFormat, ScanMode


class _EnvSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VS_", env_ignore_empty=True)

    config: str | None = None           # VS_CONFIG — path to TOML config file
    targets: list[str] | None = None
    timeout: int | None = None
    max_concurrent: int | None = None
    mode: str | None = None
    rate_limit: int | None = None
    include_categories: list[str] | None = None
    exclude_categories: list[str] | None = None
    include_tools: list[str] | None = None
    exclude_tools: list[str] | None = None
    report_format: str | None = None
    formats: list[str] | None = None
    output_dir: str | None = None
    report_min_severity: str | None = None   # VS_REPORT_MIN_SEVERITY=medium
    defectdojo_url: str | None = None
    defectdojo_api_key: str | None = None
    defectdojo_product: str | None = None
    defectdojo_engagement: str | None = None
    # LLM settings (VS_LLM_*)
    llm_enabled: str | None = None
    llm_base_url: str | None = None
    llm_api_key: str | None = None
    llm_model: str | None = None
    llm_organization: str | None = None
    llm_timeout: float | None = None
    llm_max_retries: int | None = None
    llm_temperature: float | None = None
    llm_top_p: float | None = None
    llm_max_tokens: int | None = None
    llm_frequency_penalty: float | None = None
    llm_presence_penalty: float | None = None
    llm_seed: int | None = None
    llm_min_severity: str | None = None   # VS_LLM_MIN_SEVERITY=medium
    # Per-feature toggles: VS_LLM_FEATURE_<NAME>=true|false
    llm_feature_logs_analysis: str | None = None
    llm_feature_enrich: str | None = None
    llm_feature_classify: str | None = None
    llm_feature_cluster: str | None = None
    llm_feature_mitigation: str | None = None
    llm_feature_generate_poc: str | None = None
    llm_feature_execute_poc: str | None = None
    llm_feature_false_positive_filter: str | None = None
    # PoC mechanics
    llm_poc_allow_git_clone: str | None = None
    llm_poc_languages: list[str] | None = None
    llm_poc_timeout: int | None = None
    llm_poc_max_pocs: int | None = None
    # Auth (VS_AUTH_*)
    auth_bearer_token: str | None = None
    auth_username: str | None = None
    auth_password: str | None = None
    auth_login_url: str | None = None
    # Plugins
    plugins_enabled: str | None = None
    plugins_dirs: list[str] | None = None
    # Proxy (VS_PROXY)
    proxy: str | None = None
    # Scope (VS_SCOPE_INCLUDE / VS_SCOPE_EXCLUDE — space-separated patterns)
    scope_include: str | None = None
    scope_exclude: str | None = None
    # Nuclei (VS_NUCLEI_*)
    nuclei_update_templates: str | None = None
    nuclei_headless: str | None = None
    nuclei_new_templates: str | None = None
    # Recon (VS_NO_RECON)
    no_recon: str | None = None


def _parse_bool_env(v: str | None) -> bool | None:
    if v is None:
        return None
    return v.lower() in ("1", "true", "yes", "on")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="Automated vulnerability assessment scanner and report generator.",
    )
    parser.add_argument(
        "--config", metavar="FILE",
        help="Path to a TOML config file (default: config.toml). (env: VS_CONFIG)",
    )
    parser.add_argument(
        "--targets", nargs="+", metavar="TARGET",
        help="IPs, CIDR ranges, hostnames, URLs, or paths to scan. (env: VS_TARGETS)",
    )
    parser.add_argument("--timeout", type=int, metavar="SECONDS",
                        help="Per-tool execution timeout in seconds. (env: VS_TIMEOUT)")
    parser.add_argument("--max-concurrent", type=int, metavar="N",
                        help="Max tools running concurrently. (env: VS_MAX_CONCURRENT)")
    parser.add_argument(
        "--mode", choices=[m.value for m in ScanMode], default=None,
        help="Scan aggressiveness mode. (env: VS_MODE)",
    )
    parser.add_argument("--rate-limit", type=int, metavar="RPS",
                        help="Max requests per second. (env: VS_RATE_LIMIT)")
    parser.add_argument("--include-categories", nargs="+", metavar="CATEGORY")
    parser.add_argument("--exclude-categories", nargs="+", metavar="CATEGORY")
    parser.add_argument("--include-tools", nargs="+", metavar="TOOL")
    parser.add_argument("--exclude-tools", nargs="+", metavar="TOOL")
    parser.add_argument(
        "--formats", nargs="+",
        choices=[f.value for f in ReportFormat],
        metavar="FORMAT",
        help="Report output formats (markdown/html/json, repeatable). (env: VS_FORMATS)",
    )
    # Legacy single --format alias kept for back-compat
    parser.add_argument(
        "--format", choices=[f.value for f in ReportFormat], default=None,
        metavar="FORMAT", help=argparse.SUPPRESS,
    )
    parser.add_argument("--output-dir", metavar="DIR",
                        help="Directory where reports are written. (env: VS_OUTPUT_DIR)")
    parser.add_argument(
        "--report-min-severity",
        choices=["none", "info", "low", "medium", "high", "critical"],
        default=None, metavar="LEVEL", dest="report_min_severity",
        help="Exclude findings below this severity from reports "
             "(none = include all, default: none). (env: VS_REPORT_MIN_SEVERITY)",
    )
    parser.add_argument("--defectdojo-url", metavar="URL")
    parser.add_argument("--defectdojo-api-key", metavar="KEY")
    # LLM flags
    parser.add_argument("--llm-model", metavar="MODEL",
                        help="LLM model name (required when LLM active). (env: VS_LLM_MODEL)")
    parser.add_argument("--no-llm", action="store_true",
                        help="Disable LLM analysis entirely.")
    parser.add_argument(
        "--llm-min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        metavar="LEVEL", dest="llm_min_severity",
        help="Minimum finding severity to send to LLM (default: medium). "
             "(env: VS_LLM_MIN_SEVERITY)",
    )
    parser.add_argument(
        "--llm-feature", nargs="+", metavar="NAME=on|off",
        dest="llm_features",
        help="Override a global LLM feature flag, e.g. --llm-feature generate_poc=on",
    )
    parser.add_argument("--llm-poc-execute", action="store_true",
                        help="Enable PoC execution (container-only).")
    # Auth flags
    parser.add_argument("--auth-bearer", metavar="TOKEN",
                        help="Bearer token for authenticated scanning. (env: VS_AUTH_BEARER_TOKEN)")
    parser.add_argument("--auth-user", metavar="USERNAME",
                        help="HTTP Basic username. (env: VS_AUTH_USERNAME)")
    parser.add_argument("--auth-pass", metavar="PASSWORD",
                        help="HTTP Basic password. (env: VS_AUTH_PASSWORD)")
    parser.add_argument("--auth-login-url", metavar="URL",
                        help="Form login URL. (env: VS_AUTH_LOGIN_URL)")
    parser.add_argument("--auth-cookie", nargs="+", metavar="NAME=VALUE",
                        dest="auth_cookies",
                        help="Cookies for authenticated scanning, e.g. --auth-cookie session=abc")
    parser.add_argument("--auth-header", nargs="+", metavar="NAME=VALUE",
                        dest="auth_headers",
                        help="Extra request headers, e.g. --auth-header X-API-Key=secret")
    # Plugin flags
    parser.add_argument("--no-plugins", action="store_true",
                        help="Disable plugin auto-discovery.")
    parser.add_argument("--plugin-dir", nargs="+", metavar="DIR",
                        dest="plugin_dirs",
                        help="Extra directories to scan for plugins.")

    # Scope
    parser.add_argument("--scope-include", nargs="+", metavar="PATTERN",
                        dest="scope_include",
                        help="In-scope patterns: *.example.com, 10.0.0.0/8. "
                             "Discovered assets outside this list are dropped.")
    parser.add_argument("--scope-exclude", nargs="+", metavar="PATTERN",
                        dest="scope_exclude",
                        help="Out-of-scope patterns (always denied, even if in include).")

    # Proxy
    parser.add_argument("--proxy", metavar="URL",
                        help="Route all tool traffic through this proxy "
                             "(e.g. http://127.0.0.1:8080 for Burp Suite).")

    # Nuclei
    parser.add_argument("--nuclei-update-templates", action="store_true",
                        dest="nuclei_update_templates",
                        help="Run nuclei -update-templates before scanning.")
    parser.add_argument("--nuclei-tags", nargs="+", metavar="TAG",
                        dest="nuclei_tags",
                        help="Override Nuclei tag filter (replaces mode defaults).")
    parser.add_argument("--nuclei-etags", nargs="+", metavar="TAG",
                        dest="nuclei_etags",
                        help="Additional Nuclei tags to exclude.")
    parser.add_argument("--nuclei-severity", nargs="+", metavar="SEVERITY",
                        dest="nuclei_severity",
                        help="Comma-separated severity list override (info,low,medium,high,critical).")
    parser.add_argument("--nuclei-templates", metavar="DIR",
                        dest="nuclei_templates_dir",
                        help="Custom nuclei templates directory.")
    parser.add_argument("--nuclei-headless", action="store_true",
                        dest="nuclei_headless",
                        help="Enable headless browser mode in Nuclei.")
    parser.add_argument("--nuclei-new-templates", action="store_true",
                        dest="nuclei_new_templates",
                        help="Only run templates new since last update.")

    # Recon pipeline
    parser.add_argument("--no-recon", action="store_true",
                        dest="no_recon",
                        help="Disable the asset-discovery recon pipeline.")

    parser.add_argument(
        "--dry-run", action="store_true", dest="dry_run",
        help="Print what would run (tool×target matrix) and exit without scanning.",
    )
    parser.add_argument(
        "--list-tools", action="store_true", dest="list_tools",
        help="List all registered tools with category and target types, then exit.",
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging.")
    return parser


def _load_toml(path: Path) -> dict[str, Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


def _parse_feature_flags(args_features: list[str] | None) -> dict[str, bool]:
    result: dict[str, bool] = {}
    if not args_features:
        return result
    for item in args_features:
        if "=" not in item:
            continue
        name, val = item.split("=", 1)
        result[name.strip().lower()] = val.strip().lower() in ("on", "true", "1", "yes")
    return result


def load_config(args: Namespace) -> AppConfig:
    """Build AppConfig by merging sources: TOML < env vars < CLI args."""

    # --- layer 1: TOML ---
    # Priority: CLI --config > VS_CONFIG env var > config.toml in cwd
    toml_data: dict[str, Any] = {}
    env_cfg = _EnvSettings()  # type: ignore[call-arg]
    _cfg_path_str = args.config or env_cfg.config or "config.toml"
    config_path = Path(_cfg_path_str)
    if config_path.is_file():
        toml_data = _load_toml(config_path)
    elif args.config or env_cfg.config:
        # Explicitly requested but not found — warn rather than silently skip
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "Config file not found: %s — using defaults.", config_path
        )

    # --- layer 2: env vars ---
    env = env_cfg  # already constructed above

    data = toml_data.copy()
    data.setdefault("scan", {})
    data.setdefault("scope", {})
    data.setdefault("categories", {})
    data.setdefault("tools", {})
    data.setdefault("report", {})
    data.setdefault("defectdojo", {})
    data.setdefault("llm", {})
    data.setdefault("nuclei", {})
    data.setdefault("recon", {})

    # [scan.auth] in TOML nests under scan for readability, but AppConfig.auth
    # is a top-level field.  Hoist it out before the env/CLI layers write to it.
    if "auth" not in data and "auth" in data["scan"]:
        data["auth"] = data["scan"].pop("auth")

    # scan
    if env.targets is not None:
        data["scan"]["targets"] = env.targets
    if env.timeout is not None:
        data["scan"]["timeout"] = env.timeout
    if env.max_concurrent is not None:
        data["scan"]["max_concurrent"] = env.max_concurrent
    if env.mode is not None:
        data["scan"]["mode"] = env.mode
    if env.rate_limit is not None:
        data["scan"]["rate_limit"] = env.rate_limit
    if env.include_categories is not None:
        data["categories"]["include"] = env.include_categories
    if env.exclude_categories is not None:
        data["categories"]["exclude"] = env.exclude_categories
    if env.include_tools is not None:
        data["tools"]["include"] = env.include_tools
    if env.exclude_tools is not None:
        data["tools"]["exclude"] = env.exclude_tools
    if env.formats is not None:
        data["report"]["formats"] = env.formats
    elif env.report_format is not None:
        data["report"]["formats"] = [env.report_format]
    if env.output_dir is not None:
        data["report"]["output_dir"] = env.output_dir
    if env.report_min_severity is not None:
        data["report"]["min_severity"] = env.report_min_severity
    if env.defectdojo_url is not None:
        data["defectdojo"]["url"] = env.defectdojo_url
    if env.defectdojo_api_key is not None:
        data["defectdojo"]["api_key"] = env.defectdojo_api_key
    if env.defectdojo_product is not None:
        data["defectdojo"]["product_name"] = env.defectdojo_product
    if env.defectdojo_engagement is not None:
        data["defectdojo"]["engagement_name"] = env.defectdojo_engagement

    # LLM env layer — honor standard OPENAI_* as fallback
    llm = data["llm"]
    _openai_key = os.environ.get("OPENAI_API_KEY", "")
    _openai_base = os.environ.get("OPENAI_BASE_URL", "")
    if _openai_key and not llm.get("api_key"):
        llm["api_key"] = _openai_key
    if _openai_base and not llm.get("base_url"):
        llm["base_url"] = _openai_base

    if env.llm_enabled is not None:
        raw = env.llm_enabled.lower()
        if raw in ("true", "1", "yes"):
            llm["enabled"] = True
        elif raw in ("false", "0", "no"):
            llm["enabled"] = False
        else:
            llm["enabled"] = "auto"
    if env.llm_api_key is not None:
        llm["api_key"] = env.llm_api_key
    if env.llm_base_url is not None:
        llm["base_url"] = env.llm_base_url
    if env.llm_model is not None:
        llm["model"] = env.llm_model
    if env.llm_organization is not None:
        llm["organization"] = env.llm_organization
    if env.llm_timeout is not None:
        llm["timeout"] = env.llm_timeout
    if env.llm_max_retries is not None:
        llm["max_retries"] = env.llm_max_retries
    if env.llm_temperature is not None:
        llm["temperature"] = env.llm_temperature
    if env.llm_top_p is not None:
        llm["top_p"] = env.llm_top_p
    if env.llm_max_tokens is not None:
        llm["max_tokens"] = env.llm_max_tokens
    if env.llm_frequency_penalty is not None:
        llm["frequency_penalty"] = env.llm_frequency_penalty
    if env.llm_presence_penalty is not None:
        llm["presence_penalty"] = env.llm_presence_penalty
    if env.llm_seed is not None:
        llm["seed"] = env.llm_seed
    if env.llm_min_severity is not None:
        llm["min_severity"] = env.llm_min_severity

    # Per-feature env overrides
    llm.setdefault("features", {})
    for feat in (
        "logs_analysis", "enrich", "classify", "cluster", "mitigation",
        "generate_poc", "execute_poc", "false_positive_filter",
    ):
        env_attr = f"llm_feature_{feat}"
        env_val = _parse_bool_env(getattr(env, env_attr, None))
        if env_val is not None:
            llm["features"][feat] = env_val

    # PoC env overrides
    llm.setdefault("poc", {})
    if env.llm_poc_allow_git_clone is not None:
        llm["poc"]["allow_git_clone"] = _parse_bool_env(env.llm_poc_allow_git_clone)
    if env.llm_poc_languages is not None:
        llm["poc"]["languages"] = env.llm_poc_languages
    if env.llm_poc_timeout is not None:
        llm["poc"]["timeout"] = env.llm_poc_timeout
    if env.llm_poc_max_pocs is not None:
        llm["poc"]["max_pocs"] = env.llm_poc_max_pocs

    # Auth env layer (VS_AUTH_*)
    data.setdefault("auth", {})
    if env.auth_bearer_token is not None:
        data["auth"]["bearer_token"] = env.auth_bearer_token
    if env.auth_username is not None:
        data["auth"]["username"] = env.auth_username
    if env.auth_password is not None:
        data["auth"]["password"] = env.auth_password
    if env.auth_login_url is not None:
        data["auth"]["login_url"] = env.auth_login_url

    # Plugins env layer
    data.setdefault("plugins", {})
    if env.plugins_enabled is not None:
        data["plugins"]["enabled"] = _parse_bool_env(env.plugins_enabled)
    if env.plugins_dirs is not None:
        data["plugins"]["dirs"] = env.plugins_dirs

    # Proxy env layer
    if env.proxy is not None:
        data.setdefault("scan", {})["proxy"] = env.proxy

    # Scope env layer (space-separated patterns)
    if env.scope_include is not None:
        data["scope"]["include"] = env.scope_include.split()
    if env.scope_exclude is not None:
        data["scope"]["exclude"] = env.scope_exclude.split()

    # Nuclei env layer
    if env.nuclei_update_templates is not None:
        data["nuclei"]["update_templates"] = _parse_bool_env(env.nuclei_update_templates)
    if env.nuclei_headless is not None:
        data["nuclei"]["headless"] = _parse_bool_env(env.nuclei_headless)
    if env.nuclei_new_templates is not None:
        data["nuclei"]["only_new_templates"] = _parse_bool_env(env.nuclei_new_templates)

    # Recon env layer
    if env.no_recon is not None and _parse_bool_env(env.no_recon):
        data["recon"]["enabled"] = False

    # --- layer 3: CLI args ---
    if args.targets:
        data["scan"]["targets"] = args.targets
    if args.timeout is not None:
        data["scan"]["timeout"] = args.timeout
    if args.max_concurrent is not None:
        data["scan"]["max_concurrent"] = args.max_concurrent
    if args.mode is not None:
        data["scan"]["mode"] = args.mode
    if args.rate_limit is not None:
        data["scan"]["rate_limit"] = args.rate_limit
    if args.include_categories:
        data["categories"]["include"] = args.include_categories
    if args.exclude_categories:
        data["categories"]["exclude"] = args.exclude_categories
    if args.include_tools:
        data["tools"]["include"] = args.include_tools
    if args.exclude_tools:
        data["tools"]["exclude"] = args.exclude_tools
    if args.formats:
        data["report"]["formats"] = args.formats
    elif args.format:
        data["report"]["formats"] = [args.format]
    if args.output_dir:
        data["report"]["output_dir"] = args.output_dir
    if getattr(args, "report_min_severity", None):
        data["report"]["min_severity"] = args.report_min_severity
    if args.defectdojo_url:
        data["defectdojo"]["url"] = args.defectdojo_url
    if args.defectdojo_api_key:
        data["defectdojo"]["api_key"] = args.defectdojo_api_key
    if getattr(args, "no_llm", False):
        data["llm"]["enabled"] = False
    if getattr(args, "llm_model", None):
        data["llm"]["model"] = args.llm_model
    if getattr(args, "llm_min_severity", None):
        data["llm"]["min_severity"] = args.llm_min_severity
    if getattr(args, "llm_poc_execute", False):
        data["llm"].setdefault("features", {})["execute_poc"] = True

    # CLI per-feature overrides
    cli_feature_overrides = _parse_feature_flags(getattr(args, "llm_features", None))
    if cli_feature_overrides:
        data["llm"].setdefault("features", {}).update(cli_feature_overrides)

    # Auth CLI layer
    data.setdefault("auth", {})
    if getattr(args, "auth_bearer", None):
        data["auth"]["bearer_token"] = args.auth_bearer
    if getattr(args, "auth_user", None):
        data["auth"]["username"] = args.auth_user
    if getattr(args, "auth_pass", None):
        data["auth"]["password"] = args.auth_pass
    if getattr(args, "auth_login_url", None):
        data["auth"]["login_url"] = args.auth_login_url
    if getattr(args, "auth_cookies", None):
        cookies = {k: v for k, v in (c.split("=", 1) for c in args.auth_cookies if "=" in c)}
        data["auth"].setdefault("cookies", {}).update(cookies)
    if getattr(args, "auth_headers", None):
        headers = {k: v for k, v in (h.split("=", 1) for h in args.auth_headers if "=" in h)}
        data["auth"].setdefault("headers", {}).update(headers)

    # Plugins CLI layer
    data.setdefault("plugins", {})
    if getattr(args, "no_plugins", False):
        data["plugins"]["enabled"] = False
    if getattr(args, "plugin_dirs", None):
        data["plugins"]["dirs"] = args.plugin_dirs

    # Scope CLI layer
    if getattr(args, "scope_include", None):
        data["scope"]["include"] = args.scope_include
    if getattr(args, "scope_exclude", None):
        data["scope"]["exclude"] = args.scope_exclude

    # Proxy CLI layer
    if getattr(args, "proxy", None):
        data.setdefault("scan", {})["proxy"] = args.proxy

    # Nuclei CLI layer
    if getattr(args, "nuclei_update_templates", False):
        data["nuclei"]["update_templates"] = True
    if getattr(args, "nuclei_tags", None):
        data["nuclei"]["tags"] = args.nuclei_tags
    if getattr(args, "nuclei_etags", None):
        # Merge with existing exclude_tags rather than replace
        existing = data["nuclei"].get("exclude_tags", [])
        data["nuclei"]["exclude_tags"] = list({*existing, *args.nuclei_etags})
    if getattr(args, "nuclei_templates_dir", None):
        data["nuclei"]["templates_dir"] = args.nuclei_templates_dir
    if getattr(args, "nuclei_headless", False):
        data["nuclei"]["headless"] = True
    if getattr(args, "nuclei_new_templates", False):
        data["nuclei"]["only_new_templates"] = True

    # Recon CLI layer
    if getattr(args, "no_recon", False):
        data["recon"]["enabled"] = False

    return AppConfig.model_validate(data)
