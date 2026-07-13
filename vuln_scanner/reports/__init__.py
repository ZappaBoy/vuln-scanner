from vuln_scanner.reports.base import AbstractReporter
from vuln_scanner.reports.markdown import MarkdownReporter
from vuln_scanner.config.models import ReportFormat


def get_reporter(fmt: ReportFormat) -> AbstractReporter:
    reporters: dict[ReportFormat, type[AbstractReporter]] = {
        ReportFormat.MARKDOWN: MarkdownReporter,
    }
    cls = reporters.get(fmt)
    if cls is None:
        raise ValueError(f"Unsupported report format: {fmt!r}")
    return cls()


__all__ = ["AbstractReporter", "MarkdownReporter", "get_reporter"]
