from vuln_scanner.tools.base import AbstractTool
from vuln_scanner.tools.amass import AmassTool
from vuln_scanner.tools.gitleaks import GitleaksTool
from vuln_scanner.tools.nikto import NiktoTool
from vuln_scanner.tools.nmap import NmapTool
from vuln_scanner.tools.nuclei import NucleiTool
from vuln_scanner.tools.ssh_audit import SSHAuditTool
from vuln_scanner.tools.sslyze import SSLyzeTool
from vuln_scanner.tools.testssl import TestSSLTool
from vuln_scanner.tools.trivy import TrivyTool
from vuln_scanner.tools.wapiti import WapitiTool
from vuln_scanner.tools.wpscan import WPScanTool
from vuln_scanner.tools.zap import ZAPTool

TOOL_REGISTRY: dict[str, type[AbstractTool]] = {
    "nmap":      NmapTool,
    "nuclei":    NucleiTool,
    "nikto":     NiktoTool,
    "testssl":   TestSSLTool,
    "sslyze":    SSLyzeTool,
    "wapiti":    WapitiTool,
    "wpscan":    WPScanTool,
    "ssh-audit": SSHAuditTool,
    "trivy":     TrivyTool,
    "gitleaks":  GitleaksTool,
    "zap":       ZAPTool,
    "amass":     AmassTool,
}

__all__ = [
    "AbstractTool",
    "AmassTool",
    "GitleaksTool",
    "NiktoTool",
    "NmapTool",
    "NucleiTool",
    "SSHAuditTool",
    "SSLyzeTool",
    "TestSSLTool",
    "TrivyTool",
    "WapitiTool",
    "WPScanTool",
    "ZAPTool",
    "TOOL_REGISTRY",
]
