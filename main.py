import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from vuln_scanner.config.loader import build_arg_parser, load_config
from vuln_scanner.config.models import ReportFormat
from vuln_scanner.defectdojo import DefectDojoClient
from vuln_scanner.model import Assessment
from vuln_scanner.orchestrator import ScanOrchestrator
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
}


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    _setup_logging(args.verbose)
    log = logging.getLogger(__name__)

    config = load_config(args)

    # Load plugins (extends TOOL_REGISTRY in-place)
    plugin_registry = dict(TOOL_REGISTRY)
    load_plugins(config.plugins, plugin_registry)

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
        from vuln_scanner.tools.nuclei import update_templates, configure as nuclei_configure
        update_templates(config.nuclei)
    else:
        from vuln_scanner.tools.nuclei import configure as nuclei_configure
    nuclei_configure(config.nuclei)

    # ── Run directory — all assets for this scan go here ─────────────────────
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = Path(config.report.output_dir) / f"run_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    log.info("Run directory: %s", run_dir)

    # Point gowitness at this run's screenshots subdirectory
    from vuln_scanner.tools.gowitness import configure as gowitness_configure
    gowitness_configure(run_dir / "screenshots")

    # ── Recon pipeline (HOST targets → discovered URLs) ────────────────────────
    pipeline = ReconPipeline(config.recon, scope)
    discovered = pipeline.discover(targets)
    if discovered:
        log.info("Recon discovered %d new target(s).", len(discovered))
        targets = targets + discovered

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

    # Patch the config targets with the fully expanded list
    config.scan.targets = targets

    # ── Phase 1: Network scan (nmap/rustscan) for port-based routing ──────────
    tools = [cls() for cls in plugin_registry.values()]
    orchestrator = ScanOrchestrator(config=config, tools=tools)
    results = orchestrator.run()

    # ── Port routing: derive new web targets from open port findings ──────────
    web_from_ports = extract_web_targets(
        results,
        scope=scope,
        existing=set(targets),
    )
    if web_from_ports:
        log.info("Port routing: %d new web target(s) from open ports.", len(web_from_ports))
        config.scan.targets = targets + web_from_ports
        # Re-run web tools only on the newly discovered targets
        from vuln_scanner.tools.enums import TargetType
        web_only_tools = [
            t for t in tools
            if TargetType.URL in t.applicable_targets or not t.applicable_targets
        ]
        web_config = config.model_copy(deep=True)
        web_config.scan.targets = web_from_ports
        web_orchestrator = ScanOrchestrator(config=web_config, tools=web_only_tools)
        results = list(results) + web_orchestrator.run()

    # Assemble Assessment
    assessment = Assessment.from_results(
        results,
        metadata={"scan_mode": config.scan.mode.value, "timestamp": timestamp},
    )

    # LLM analysis (Pass 1-4: triage, PoC design, mitigation, clustering)
    if llm_config.is_active:
        from vuln_scanner.llm.analyzer import LLMAnalyzer
        analyzer = LLMAnalyzer(llm_config)
        assessment = analyzer.analyze(assessment)

    # PoC generation
    if llm_config.is_active and llm_config.features.generate_poc:
        from vuln_scanner.poc.generator import PocGenerator
        poc_cfg = llm_config.poc
        assets_dir = Path(poc_cfg.assets_dir) if poc_cfg.assets_dir else run_dir / "poc"
        generator = PocGenerator(llm_config)
        pocs = generator.generate(assessment, assets_dir)
        assessment.poc_asset_paths = [p.script_path for p in pocs if p.script_path]

        # PoC execution (container-only)
        if llm_config.features.execute_poc and pocs:
            from vuln_scanner.poc.runner import PocRunner
            runner = PocRunner(llm_config)
            pocs = runner.run_all(pocs, assessment)
            # Re-run mitigation pass with evidence (if we have pocs with verdicts)
            confirmed = [p for p in pocs if p.verdict.value in ("confirmed", "inconclusive")]
            if confirmed and llm_config.features.mitigation:
                from vuln_scanner.llm.analyzer import LLMAnalyzer
                LLMAnalyzer(llm_config)._mitigation_for_result  # noqa — called below
                # Re-run mitigation for all results that have poc evidence
                analyzer2 = LLMAnalyzer(llm_config)
                for r in assessment.results:
                    try:
                        analyzer2._mitigation_for_result(r, {})
                    except Exception:
                        pass

    # Write reports into run_dir
    for fmt in config.report.formats:
        ext = _REPORT_EXT.get(fmt, fmt.value)
        output_path = run_dir / f"report.{ext}"
        reporter = get_reporter(fmt, min_severity=config.report.min_severity)
        written = reporter.generate(assessment, output_path)
        log.info("Report written: %s", written)

    # DefectDojo push
    DefectDojoClient(config.defectdojo).push(results)


if __name__ == "__main__":
    main()
