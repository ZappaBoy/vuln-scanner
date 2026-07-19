from abc import ABC, abstractmethod
from pathlib import Path

from vuln_scanner.model import Assessment


class AbstractReporter(ABC):
    def __init__(self, min_severity: str = "none") -> None:
        self._min_severity = min_severity

    @abstractmethod
    def generate(self, assessment: Assessment, output_path: Path) -> Path:
        """Render assessment into the chosen format and write to output_path.

        Returns the path of the written file.
        """
