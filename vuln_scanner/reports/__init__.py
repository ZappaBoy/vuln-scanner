from vuln_scanner.config.models import ReportFormat
from vuln_scanner.reports.base import AbstractReporter
from vuln_scanner.reports.html import HTMLReporter
from vuln_scanner.reports.json_reporter import JSONReporter
from vuln_scanner.reports.markdown import MarkdownReporter


def get_reporter(fmt: ReportFormat) -> AbstractReporter:
    reporters: dict[ReportFormat, type[AbstractReporter]] = {
        ReportFormat.MARKDOWN: MarkdownReporter,
        ReportFormat.HTML: HTMLReporter,
        ReportFormat.JSON: JSONReporter,
    }
    cls = reporters.get(fmt)
    if cls is None:
        raise ValueError(f"Unsupported report format: {fmt!r}")
    return cls()


__all__ = [
    "AbstractReporter",
    "MarkdownReporter",
    "HTMLReporter",
    "JSONReporter",
    "get_reporter",
]
