import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from vuln_scanner.config.loader import build_arg_parser, load_config
from vuln_scanner.config.models import ReportFormat
from vuln_scanner.defectdojo import DefectDojoClient
from vuln_scanner.model import Assessment
from vuln_scanner.orchestrator import ScanOrchestrator
from vuln_scanner.reports import get_reporter
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

    if not config.scan.targets:
        log.error("No targets specified. Use --targets or set VS_TARGETS.")
        sys.exit(1)

    # Build and validate LLM config eagerly so config errors fail fast
    llm_config = config.build_llm_config()
    try:
        llm_config.validate_active()
    except ValueError as exc:
        log.error("LLM configuration error: %s", exc)
        sys.exit(1)

    log.info("Scan mode: %s", config.scan.mode.value)
    if llm_config.is_active:
        log.info("LLM analysis: enabled (model=%s)", llm_config.model)
    else:
        log.info("LLM analysis: disabled")

    # Run scan
    tools = [cls() for cls in TOOL_REGISTRY.values()]
    orchestrator = ScanOrchestrator(config=config, tools=tools)
    results = orchestrator.run()

    # Assemble Assessment
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
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
        assets_dir_str = poc_cfg.assets_dir
        if not assets_dir_str:
            assets_dir_str = str(
                Path(config.report.output_dir) / f"{timestamp}_assets" / "poc"
            )
        assets_dir = Path(assets_dir_str)
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

    # Write reports
    formats = config.report.formats
    for fmt in formats:
        ext = _REPORT_EXT.get(fmt, fmt.value)
        output_path = Path(config.report.output_dir) / f"report_{timestamp}.{ext}"
        reporter = get_reporter(fmt)
        written = reporter.generate(assessment, output_path)
        log.info("Report written: %s", written)

    # DefectDojo push
    DefectDojoClient(config.defectdojo).push(results)


if __name__ == "__main__":
    main()
