import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from vuln_scanner.config.loader import build_arg_parser, load_config
from vuln_scanner.defectdojo import DefectDojoClient
from vuln_scanner.orchestrator import ScanOrchestrator
from vuln_scanner.reports import get_reporter
from vuln_scanner.tools import TOOL_REGISTRY

_REPORT_EXT = {"markdown": "md"}


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

    log.info("Scan mode: %s", config.scan.mode.value)

    tools = [cls() for cls in TOOL_REGISTRY.values()]
    orchestrator = ScanOrchestrator(config=config, tools=tools)
    results = orchestrator.run()

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    fmt = config.report.format.value
    ext = _REPORT_EXT.get(fmt, fmt)
    output_path = Path(config.report.output_dir) / f"report_{timestamp}.{ext}"

    reporter = get_reporter(config.report.format)
    written = reporter.generate(results, output_path)
    log.info("Report written to: %s", written)

    DefectDojoClient(config.defectdojo).push(results)


if __name__ == "__main__":
    main()
