from abc import ABC, abstractmethod
from pathlib import Path

from vuln_scanner.tools.base import ScanResult


class AbstractReporter(ABC):
    @abstractmethod
    def generate(self, results: list[ScanResult], output_path: Path) -> Path:
        """Render results into the chosen format and write to output_path.

        Returns the path of the written file.
        """
