import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from vuln_scanner.config.loader import build_arg_parser, load_config
from vuln_scanner.config.models import ReportFormat
from vuln_scanner.defectdojo import DefectDojoClient
from vuln_scanner.model import Assessment
from vuln_scanner.orchestrator import ProgressAwareHandler, ScanOrchestrator
from vuln_scanner.pipeline import ReconPipeline
from vuln_scanner.plugins import load_plugins
from vuln_scanner.port_router import extract_web_targets
from vuln_scanner.reports import get_reporter
from vuln_scanner.scope import ScopeValidator
from vuln_scanner.tools import TOOL_REGISTRY

_REPORT_EXT = {
    ReportFormat.MARKDOWN: "md",
    ReportFormat.HTML: "html",
    ReportFormat.JSON: "json",
    ReportFormat.PDF: "pdf",
}

# ── Logging setup ─────────────────────────────────────────────────────────────

_FMT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_FMT_COLOR = "%(asctime)s %(levelname_color)s %(name_short)s: %(message)s"
_DATEFMT = "%H:%M:%S"

_LEVEL_COLORS = {
    logging.DEBUG: "\033[36m",  # cyan
    logging.INFO: "\033[32m",  # green
    logging.WARNING: "\033[33m",  # yellow
    logging.ERROR: "\033[31m",  # red
    logging.CRITICAL: "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


class _ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        color = _LEVEL_COLORS.get(record.levelno, "")
        record.levelname_color = f"{color}{record.levelname:<8}{_RESET}"
        # Shorten logger names: vuln_scanner.tools.nmap → tools.nmap
        parts = record.name.split(".")
        record.name_short = ".".join(parts[-2:]) if len(parts) > 2 else record.name
        return super().format(record)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)

    handler = ProgressAwareHandler(sys.stderr)
    handler.setLevel(level)
    if sys.stderr.isatty():
        handler.setFormatter(_ColorFormatter(_FMT_COLOR, datefmt=_DATEFMT))
    else:
        handler.setFormatter(logging.Formatter(_FMT, datefmt=_DATEFMT))
    root.addHandler(handler)


def _add_file_handler(log_path: Path) -> None:
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(_FMT, datefmt=_DATEFMT))
    logging.getLogger().addHandler(handler)


def _cmd_list_tools(registry: dict) -> None:
    from vuln_scanner.tools.target import _ALL_TARGET_TYPES

    tools = sorted(registry.values(), key=lambda c: (c().category, c().name))
    print(f"{len(tools)} tool(s) registered:\n")
    print(f"  {'NAME':<24} {'CATEGORY':<16} TARGET TYPES")
    print("  " + "-" * 70)
    for cls in tools:
        t = cls()
        if t.applicable_targets is _ALL_TARGET_TYPES:
            types_str = "all"
        else:
            types_str = ", ".join(sorted(tp.value for tp in t.applicable_targets))
        print(f"  {t.name:<24} {t.category:<16} {types_str}")


def _cmd_dry_run(config, registry: dict) -> None:
    from vuln_scanner.orchestrator import ScanOrchestrator

    tools = [cls() for cls in registry.values()]
    orchestrator = ScanOrchestrator(config=config, tools=tools)
    active_tools = orchestrator._filter_tools()
    targets = config.scan.targets

    tasks = [(tool, target) for tool in active_tools for target in targets if tool.applies_to(target)]

    print(
        f"Dry run — {len(tasks)} task(s) would execute "
        f"(mode={config.scan.mode.value}, workers={config.scan.max_concurrent}):\n"
    )
    print(f"  {'TOOL':<24} {'CATEGORY':<16} TARGET")
    print("  " + "-" * 72)
    for tool, target in sorted(tasks, key=lambda x: (x[0].category, x[0].name)):
        timeout = getattr(config.tools, "timeouts", {}).get(tool.name, config.scan.timeout)
        print(f"  {tool.name:<24} {tool.category:<16} {target}  (timeout={timeout}s)")
    print(f"\n  Total: {len(active_tools)} tool(s) × {len(targets)} target(s) = {len(tasks)} task(s)")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    _setup_logging(args.verbose)
    log = logging.getLogger(__name__)

    config = load_config(args)

    # Load plugins (extends TOOL_REGISTRY in-place)
    plugin_registry = dict(TOOL_REGISTRY)
    load_plugins(config.plugins, plugin_registry)

    if args.list_tools:
        _cmd_list_tools(plugin_registry)
        sys.exit(0)

    if not config.scan.targets:
        log.error("No targets specified. Use --targets or set VS_TARGETS.")
        sys.exit(1)

    # ── Scope validation ──────────────────────────────────────────────────────
    scope = ScopeValidator.from_config(config.scope)
    # Validate user-provided targets (not strict — they're explicit).
    # This removes any that are explicitly excluded.
    targets = scope.filter(config.scan.targets, discovered=False)
    if not targets:
        log.error("All targets were denied by scope rules. Check [scope] config.")
        sys.exit(1)
    if len(targets) < len(config.scan.targets):
        log.warning(
            "%d target(s) removed by scope rules.",
            len(config.scan.targets) - len(targets),
        )

    # ── Nuclei template update (pre-scan) ─────────────────────────────────────
    if config.nuclei.update_templates:
        from vuln_scanner.tools.nuclei import configure as nuclei_configure
        from vuln_scanner.tools.nuclei import update_templates

        update_templates(config.nuclei)
    else:
        from vuln_scanner.tools.nuclei import configure as nuclei_configure
    nuclei_configure(config.nuclei)

    # ── Run directory — all assets for this scan go here ─────────────────────
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = Path(config.report.output_dir) / f"run_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    _add_file_handler(run_dir / "scan.log")
    log.info("Run directory: %s", run_dir)

    # Point gowitness at this run's screenshots subdirectory
    from vuln_scanner.tools.gowitness import configure as gowitness_configure

    gowitness_configure(run_dir / "screenshots")

    # Build and validate LLM config eagerly so config errors fail fast
    llm_config = config.build_llm_config()
    try:
        llm_config.validate_active()
    except ValueError as exc:
        log.error("LLM configuration error: %s", exc)
        sys.exit(1)

    log.info("Scan mode: %s", config.scan.mode.value)
    if config.scan.proxy:
        log.info("Proxy: %s", config.scan.proxy)
    if llm_config.is_active:
        log.info("LLM analysis: enabled (model=%s)", llm_config.model)
    else:
        log.info("LLM analysis: disabled")

    # ── Phase: Recon pipeline (HOST targets → discovered URLs) ────────────────
    try:
        pipeline = ReconPipeline(config.recon, scope)
        discovered = pipeline.discover(targets)
        if discovered:
            log.info("Recon discovered %d new target(s).", len(discovered))
            targets = targets + discovered
    except Exception:
        log.exception("Recon pipeline failed — continuing with original targets.")

    # Patch the config targets with the fully expanded list
    config.scan.targets = targets

    if args.dry_run:
        _cmd_dry_run(config, plugin_registry)
        sys.exit(0)

    results: list = []
    assessment: Assessment | None = None
    exit_code = 0

    # ── Phase: Main scan ──────────────────────────────────────────────────────
    tool_log_dir = run_dir / "tool_logs"
    tools = [cls() for cls in plugin_registry.values()]
    orchestrator = ScanOrchestrator(config=config, tools=tools, log_dir=tool_log_dir)
    try:
        results = orchestrator.run()
    except Exception:
        log.exception("Main scan failed.")
        exit_code = 1

    # ── Phase: Port routing ───────────────────────────────────────────────────
    try:
        web_from_ports = extract_web_targets(results, scope=scope, existing=set(targets))
        if web_from_ports:
            log.info("Port routing: %d new web target(s) from open ports.", len(web_from_ports))
            config.scan.targets = targets + web_from_ports
            from vuln_scanner.tools.enums import TargetType

            web_only_tools = [t for t in tools if TargetType.URL in t.applicable_targets or not t.applicable_targets]
            web_config = config.model_copy(deep=True)
            web_config.scan.targets = web_from_ports
            web_orchestrator = ScanOrchestrator(config=web_config, tools=web_only_tools, log_dir=tool_log_dir)
            results = list(results) + web_orchestrator.run()
    except Exception:
        log.exception("Port routing scan failed — using main scan results.")

    # ── Phase: Assessment assembly ────────────────────────────────────────────
    try:
        assessment = Assessment.from_results(
            results,
            metadata={"scan_mode": config.scan.mode.value, "timestamp": timestamp},
        )
    except Exception:
        log.exception("Assessment assembly failed.")
        exit_code = 1

    # ── Phase: LLM analysis ───────────────────────────────────────────────────
    analyzer = None
    if assessment is not None and llm_config.is_active:
        try:
            from vuln_scanner.llm.analyzer import LLMAnalyzer

            analyzer = LLMAnalyzer(llm_config)
            assessment = analyzer.analyze(assessment)
        except Exception:
            log.exception("LLM analysis failed — report will not include AI triage.")

    # ── Phase: PoC generation & execution ────────────────────────────────────
    if assessment is not None and llm_config.is_active and llm_config.features.generate_poc:
        try:
            from vuln_scanner.poc.generator import PocGenerator

            poc_cfg = llm_config.poc
            assets_dir = Path(poc_cfg.assets_dir) if poc_cfg.assets_dir else run_dir / "poc"
            generator = PocGenerator(llm_config)
            pocs = generator.generate(assessment, assets_dir)
            assessment.poc_asset_paths = [p.script_path for p in pocs if p.script_path]

            if llm_config.features.execute_poc and pocs:
                from vuln_scanner.poc.runner import PocRunner

                runner = PocRunner(llm_config)
                pocs = runner.run_all(pocs, assessment)
                confirmed = [p for p in pocs if p.verdict.value in ("confirmed", "inconclusive")]
                if confirmed and llm_config.features.mitigation and analyzer is not None:
                    poc_plans = assessment.metadata.get("llm_poc_plans", {})
                    for r in assessment.results:
                        try:
                            analyzer._mitigation_for_result(r, poc_plans)
                        except Exception as exc:
                            log.warning("Post-PoC mitigation failed for %s/%s: %s", r.tool, r.target, exc)
        except Exception:
            log.exception("PoC phase failed — continuing without PoC artifacts.")

    # ── Phase: Report writing ─────────────────────────────────────────────────
    # If assembly failed but we have raw results, build a minimal partial report.
    if assessment is None and results:
        log.warning("Building partial report from %d raw result(s).", len(results))
        try:
            assessment = Assessment.from_results(
                results,
                metadata={
                    "scan_mode": config.scan.mode.value,
                    "timestamp": timestamp,
                    "partial": True,
                },
            )
        except Exception:
            log.exception("Could not build partial assessment — no report written.")

    if assessment is not None:
        for fmt in config.report.formats:
            ext = _REPORT_EXT.get(fmt, fmt.value)
            output_path = run_dir / f"report.{ext}"
            try:
                reporter = get_reporter(fmt, min_severity=config.report.min_severity)
                written = reporter.generate(assessment, output_path)
                log.info("Report written: %s", written)
            except Exception:
                log.exception("Report generation failed for format '%s'.", fmt.value)
                exit_code = 1

    # ── DefectDojo push ───────────────────────────────────────────────────────
    try:
        DefectDojoClient(config.defectdojo).push(results)
    except Exception:
        log.exception("DefectDojo push failed.")

    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
