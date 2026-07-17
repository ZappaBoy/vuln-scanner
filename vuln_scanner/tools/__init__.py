from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.acunetix import AcunetixTool
from vuln_scanner.tools.alterx import AlterxTool
from vuln_scanner.tools.bearer import BearerTool
from vuln_scanner.tools.brakeman import BrakemanTool
from vuln_scanner.tools.cariddi import CariddiTool
from vuln_scanner.tools.crlfuzz import CRLFuzzTool
from vuln_scanner.tools.detect_secrets import DetectSecretsTool
from vuln_scanner.tools.flawfinder import FlawfinderTool
from vuln_scanner.tools.govulncheck import GovulncheckTool
from vuln_scanner.tools.hadolint import HadolintTool
from vuln_scanner.tools.horusec import HorusecTool
from vuln_scanner.tools.httprobe import HttprobeTool
from vuln_scanner.tools.kubebench import KubeBenchTool
from vuln_scanner.tools.linkfinder import LinkFinderTool
from vuln_scanner.tools.noseyparker import NoseyParkerTool
from vuln_scanner.tools.npm_audit import NpmAuditTool
from vuln_scanner.tools.osv_scanner import OSVScannerTool
from vuln_scanner.tools.prowler import ProwlerTool
from vuln_scanner.tools.puredns import PureDNSTool
from vuln_scanner.tools.smuggler import SmugglerTool
from vuln_scanner.tools.terrascan import TerrascanTool
from vuln_scanner.tools.waybackurls import WaybackURLsTool
from vuln_scanner.tools.amass import AmassTool
from vuln_scanner.tools.apifuzzer import APIFuzzerTool
from vuln_scanner.tools.arachni import ArachniTool
from vuln_scanner.tools.arjun import ArjunTool
from vuln_scanner.tools.bandit import BanditTool
from vuln_scanner.tools.checkov import CheckovTool
from vuln_scanner.tools.cherrybomb import CherrybombTool
from vuln_scanner.tools.commix import CommixTool
from vuln_scanner.tools.corscanner import CORScannerTool
from vuln_scanner.tools.crackmapexec import CrackMapExecTool
from vuln_scanner.tools.dalfox import DalfoxTool
from vuln_scanner.tools.dependency_check import DependencyCheckTool
from vuln_scanner.tools.dnsrecon import DNSReconTool
from vuln_scanner.tools.dnsx import DnsxTool
from vuln_scanner.tools.drheader import DrheaderTool
from vuln_scanner.tools.enum4linux import Enum4linuxTool
from vuln_scanner.tools.feroxbuster import FeroxbusterTool
from vuln_scanner.tools.ffuf import FfufTool
from vuln_scanner.tools.fierce import FierceTool
from vuln_scanner.tools.gau import GauTool
from vuln_scanner.tools.gitleaks import GitleaksTool
from vuln_scanner.tools.gobuster import GobusterTool
from vuln_scanner.tools.gosec import GosecTool
from vuln_scanner.tools.graphql_cop import GraphQLCopTool
from vuln_scanner.tools.grype import GrypeTool
from vuln_scanner.tools.hakrawler import HakrawlerTool
from vuln_scanner.tools.httpx import HttpxTool
from vuln_scanner.tools.humble import HumbleTool
from vuln_scanner.tools.jsluice import JSluiceTool
from vuln_scanner.tools.katana import KatanaTool
from vuln_scanner.tools.kiterunner import KiterunnerTool
from vuln_scanner.tools.masscan import MasscanTool
from vuln_scanner.tools.naabu import NaabuTool
from vuln_scanner.tools.netdiscover import NetdiscoverTool
from vuln_scanner.tools.nikto import NiktoTool
from vuln_scanner.tools.nmap import NmapTool
from vuln_scanner.tools.nosqlmap import NoSQLMapTool
from vuln_scanner.tools.nuclei import NucleiTool
from vuln_scanner.tools.openvas import OpenVASTool
from vuln_scanner.tools.paramspider import ParamSpiderTool
from vuln_scanner.tools.pip_audit import PipAuditTool
from vuln_scanner.tools.restler import RESTlerTool
from vuln_scanner.tools.rustscan import RustScanTool
from vuln_scanner.tools.secretfinder import SecretFinderTool
from vuln_scanner.tools.sqlmap import SQLMapTool
from vuln_scanner.tools.semgrep import SemgrepTool
from vuln_scanner.tools.smbmap import SMBMapTool
from vuln_scanner.tools.ssh_audit import SSHAuditTool
from vuln_scanner.tools.sslyze import SSLyzeTool
from vuln_scanner.tools.sslscan import SSLScanTool
from vuln_scanner.tools.subfinder import SubfinderTool
from vuln_scanner.tools.testssl import TestSSLTool
from vuln_scanner.tools.tfsec import TfsecTool
from vuln_scanner.tools.theharvester import TheHarvesterTool
from vuln_scanner.tools.tls_attacker import TLSAttackerTool
from vuln_scanner.tools.tlsx import TlsxTool
from vuln_scanner.tools.trivy import TrivyTool
from vuln_scanner.tools.trufflehog import TrufflehogTool
from vuln_scanner.tools.wafw00f import WafW00fTool
from vuln_scanner.tools.wapiti import WapitiTool
from vuln_scanner.tools.whatweb import WhatWebTool
from vuln_scanner.tools.wfuzz import WfuzzTool
from vuln_scanner.tools.wpscan import WPScanTool
from vuln_scanner.tools.xsstrike import XSStrikeTool
from vuln_scanner.tools.zap import ZAPTool

TOOL_REGISTRY: dict[str, type[AbstractTool]] = {
    # Web application scanning
    "nmap":               NmapTool,
    "nuclei":             NucleiTool,
    "nikto":              NiktoTool,
    "wapiti":             WapitiTool,
    "wpscan":             WPScanTool,
    "zap":                ZAPTool,
    "drheader":           DrheaderTool,
    "arachni":            ArachniTool,
    "acunetix":           AcunetixTool,
    "sqlmap":             SQLMapTool,
    "ffuf":               FfufTool,
    "feroxbuster":        FeroxbusterTool,
    "gobuster":           GobusterTool,
    "wfuzz":              WfuzzTool,
    "dalfox":             DalfoxTool,
    "commix":             CommixTool,
    "whatweb":            WhatWebTool,
    "wafw00f":            WafW00fTool,
    "katana":             KatanaTool,
    "httpx":              HttpxTool,
    "arjun":              ArjunTool,
    "corscanner":         CORScannerTool,
    "hakrawler":          HakrawlerTool,
    "xsstrike":           XSStrikeTool,
    "nosqlmap":           NoSQLMapTool,
    "graphql-cop":        GraphQLCopTool,
    "paramspider":        ParamSpiderTool,
    "gau":                GauTool,
    "jsluice":            JSluiceTool,
    # SSL/TLS
    "testssl":            TestSSLTool,
    "sslyze":             SSLyzeTool,
    "sslscan":            SSLScanTool,
    "humble":             HumbleTool,
    "tls-attacker":       TLSAttackerTool,
    "tlsx":               TlsxTool,
    # Network / recon
    "ssh-audit":          SSHAuditTool,
    "amass":              AmassTool,
    "openvas":            OpenVASTool,
    "masscan":            MasscanTool,
    "rustscan":           RustScanTool,
    "subfinder":          SubfinderTool,
    "dnsx":               DnsxTool,
    "dnsrecon":           DNSReconTool,
    "enum4linux-ng":      Enum4linuxTool,
    "smbmap":             SMBMapTool,
    "crackmapexec":       CrackMapExecTool,
    "netdiscover":        NetdiscoverTool,
    "theharvester":       TheHarvesterTool,
    "fierce":             FierceTool,
    "naabu":              NaabuTool,
    # Container / SCA
    "trivy":              TrivyTool,
    "grype":              GrypeTool,
    "dependency-check":   DependencyCheckTool,
    "pip-audit":          PipAuditTool,
    # SAST
    "semgrep":            SemgrepTool,
    "bandit":             BanditTool,
    "gosec":              GosecTool,
    # IaC
    "checkov":            CheckovTool,
    "tfsec":              TfsecTool,
    # Secrets
    "gitleaks":           GitleaksTool,
    "trufflehog":         TrufflehogTool,
    "secretfinder":       SecretFinderTool,
    # API security
    "kiterunner":         KiterunnerTool,
    "apifuzzer":          APIFuzzerTool,
    "restler":            RESTlerTool,
    "cherrybomb":         CherrybombTool,
    # Cloud & IaC
    "prowler":            ProwlerTool,
    "kube-bench":         KubeBenchTool,
    "terrascan":          TerrascanTool,
    "hadolint":           HadolintTool,
    # SCA (additional)
    "osv-scanner":        OSVScannerTool,
    "npm-audit":          NpmAuditTool,
    "govulncheck":        GovulncheckTool,
    # Web (additional)
    "crlfuzz":            CRLFuzzTool,
    "smuggler":           SmugglerTool,
    "linkfinder":         LinkFinderTool,
    "cariddi":            CariddiTool,
    # DNS / Recon (additional)
    "puredns":            PureDNSTool,
    "alterx":             AlterxTool,
    "waybackurls":        WaybackURLsTool,
    "httprobe":           HttprobeTool,
    # SAST (additional)
    "bearer":             BearerTool,
    "horusec":            HorusecTool,
    "brakeman":           BrakemanTool,
    "flawfinder":         FlawfinderTool,
    # Secrets (additional)
    "detect-secrets":     DetectSecretsTool,
    "noseyparker":        NoseyParkerTool,
}

__all__ = [
    "AbstractTool",
    "AcunetixTool",
    "AmassTool",
    "APIFuzzerTool",
    "ArachniTool",
    "ArjunTool",
    "BanditTool",
    "CheckovTool",
    "CherrybombTool",
    "CommixTool",
    "CORScannerTool",
    "CrackMapExecTool",
    "DalfoxTool",
    "DependencyCheckTool",
    "DNSReconTool",
    "DnsxTool",
    "DrheaderTool",
    "Enum4linuxTool",
    "FeroxbusterTool",
    "FfufTool",
    "FierceTool",
    "GauTool",
    "GitleaksTool",
    "GobusterTool",
    "GosecTool",
    "GraphQLCopTool",
    "GrypeTool",
    "HakrawlerTool",
    "HttpxTool",
    "HumbleTool",
    "JSluiceTool",
    "KatanaTool",
    "KiterunnerTool",
    "MasscanTool",
    "NaabuTool",
    "NetdiscoverTool",
    "NiktoTool",
    "NmapTool",
    "NoSQLMapTool",
    "NucleiTool",
    "OpenVASTool",
    "ParamSpiderTool",
    "PipAuditTool",
    "RESTlerTool",
    "RustScanTool",
    "SecretFinderTool",
    "SemgrepTool",
    "SMBMapTool",
    "SQLMapTool",
    "SSHAuditTool",
    "SSLScanTool",
    "SSLyzeTool",
    "SubfinderTool",
    "TestSSLTool",
    "TfsecTool",
    "TheHarvesterTool",
    "TLSAttackerTool",
    "TlsxTool",
    "TrivyTool",
    "TrufflehogTool",
    "WafW00fTool",
    "WapitiTool",
    "WhatWebTool",
    "WfuzzTool",
    "WPScanTool",
    "XSStrikeTool",
    "ZAPTool",
    "AlterxTool",
    "BearerTool",
    "BrakemanTool",
    "CariddiTool",
    "CRLFuzzTool",
    "DetectSecretsTool",
    "FlawfinderTool",
    "GovulncheckTool",
    "HadolintTool",
    "HorusecTool",
    "HttprobeTool",
    "KubeBenchTool",
    "LinkFinderTool",
    "NoseyParkerTool",
    "NpmAuditTool",
    "OSVScannerTool",
    "ProwlerTool",
    "PureDNSTool",
    "SmugglerTool",
    "TerrascanTool",
    "WaybackURLsTool",
    "TOOL_REGISTRY",
]
