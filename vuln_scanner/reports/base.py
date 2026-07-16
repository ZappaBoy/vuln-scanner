from abc import ABC, abstractmethod
from pathlib import Path

from vuln_scanner.model import Assessment


class AbstractReporter(ABC):
    @abstractmethod
    def generate(self, assessment: Assessment, output_path: Path) -> Path:
        """Render assessment into the chosen format and write to output_path.

        Returns the path of the written file.
        """
