"""Full structured JSON reporter — exports the complete Assessment model."""


import json
from pathlib import Path

from vuln_scanner.model import Assessment
from vuln_scanner.reports.base import AbstractReporter
from vuln_scanner.tools.enums import severity_passes, _parse_severity


class JSONReporter(AbstractReporter):
    def generate(self, assessment: Assessment, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = assessment.model_dump(mode="json")
        if self._min_severity and self._min_severity.lower() not in ("none", ""):
            for result in data.get("results", []):
                result["findings"] = [
                    f for f in result.get("findings", [])
                    if severity_passes(
                        _parse_severity(f.get("severity", "info")),
                        self._min_severity,
                    )
                ]
        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return output_path
