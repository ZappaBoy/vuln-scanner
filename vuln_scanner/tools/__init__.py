from vuln_scanner.tools.base import AbstractTool
from vuln_scanner.tools.nmap import NmapTool

TOOL_REGISTRY: dict[str, type[AbstractTool]] = {
    "nmap": NmapTool,
}

__all__ = ["AbstractTool", "NmapTool", "TOOL_REGISTRY"]
