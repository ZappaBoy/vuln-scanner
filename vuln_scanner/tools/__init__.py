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
from vuln_scanner.tools.gowitness import GowitnesssTool
from vuln_scanner.tools.hydra import HydraTool
from vuln_scanner.tools.lynis import LynisTool
from vuln_scanner.tools.subjack import SubjackTool
from vuln_scanner.tools.subzy import SubzyTool
from vuln_scanner.tools.dnsreaper import DnsReaperTool
from vuln_scanner.tools.jwt_tool import JwtToolTool
from vuln_scanner.tools.tplmap import TplmapTool
from vuln_scanner.tools.git_dumper import GitDumperTool
from vuln_scanner.tools.kubescape import KubescapeTool
from vuln_scanner.tools.kube_hunter import KubeHunterTool
from vuln_scanner.tools.bbot import BbotTool
from vuln_scanner.tools.nomore403 import Nomore403Tool
from vuln_scanner.tools.checksec import ChecksecTool
from vuln_scanner.tools.h2csmuggler import H2cSmugglerTool

# Web
from vuln_scanner.tools.dirsearch import DirsearchTool
from vuln_scanner.tools.kxss import KxssTool
from vuln_scanner.tools.crlfuite import CRLFsuiteTool
from vuln_scanner.tools.ssrfmap import SSRFmapTool
from vuln_scanner.tools.oralyzer import OralyzerTool
from vuln_scanner.tools.sstimap import SSTImapTool
from vuln_scanner.tools.corsy import CorsyTool
from vuln_scanner.tools.ghauri import GhauriTool
from vuln_scanner.tools.xsrfprobe import XSRFProbeTool
from vuln_scanner.tools.joomscan import JoomscanTool
from vuln_scanner.tools.cmsmap import CMSmapTool
from vuln_scanner.tools.aemhacker import AEMHackerTool
from vuln_scanner.tools.whatwaf import WhatWafTool
from vuln_scanner.tools.jaeles import JaelesTool
from vuln_scanner.tools.blackwidow import BlackWidowTool
from vuln_scanner.tools.jsparser import JSParserTool
from vuln_scanner.tools.parameth import ParamethTool
# Network
from vuln_scanner.tools.medusa import MedusaTool
from vuln_scanner.tools.findomain import FindomainTool
from vuln_scanner.tools.massdns import MassDNSTool
from vuln_scanner.tools.shuffledns import ShuffleDNSTool
from vuln_scanner.tools.assetfinder import AssetfinderTool
from vuln_scanner.tools.vhostscan import VHostScanTool
from vuln_scanner.tools.subdominator import SubdominatorTool
from vuln_scanner.tools.zmap_tool import ZmapTool
from vuln_scanner.tools.gotator import GotatorTool
from vuln_scanner.tools.ripgen import RipgenTool
from vuln_scanner.tools.dnsgen import DNSgenTool
from vuln_scanner.tools.gauplus import GauplusTool
from vuln_scanner.tools.haktrails import HaktrailsTool
from vuln_scanner.tools.csprecon import CspreconTool
from vuln_scanner.tools.github_subdomains import GithubSubdomainsTool
from vuln_scanner.tools.chaos_client import ChaosClientTool
from vuln_scanner.tools.knockpy import KnockpyTool
# Container / K8s
from vuln_scanner.tools.syft import SyftTool
from vuln_scanner.tools.dockle import DockleTool
from vuln_scanner.tools.docker_bench import DockerBenchTool
from vuln_scanner.tools.kubeaudit import KubeauditTool
from vuln_scanner.tools.kube_score import KubeScoreTool
from vuln_scanner.tools.kube_linter import KubeLinterTool
from vuln_scanner.tools.popeye import PopeyeTool
from vuln_scanner.tools.dive import DiveTool
# SAST
from vuln_scanner.tools.codeql import CodeQLTool
from vuln_scanner.tools.spotbugs import SpotBugsTool
from vuln_scanner.tools.pmd import PMDTool
from vuln_scanner.tools.infer import InferTool
from vuln_scanner.tools.cppcheck import CppcheckTool
from vuln_scanner.tools.devskim import DevSkimTool
from vuln_scanner.tools.eslint import ESLintTool
from vuln_scanner.tools.psalm import PsalmTool
from vuln_scanner.tools.progpilot import ProgPilotTool
from vuln_scanner.tools.rubocop import RuboCopTool
from vuln_scanner.tools.codechecker import CodeCheckerTool
from vuln_scanner.tools.dawnscanner import DawnScannerTool
from vuln_scanner.tools.joern import JoernTool
from vuln_scanner.tools.insider import InsiderTool
from vuln_scanner.tools.weggli import WeggliTool
# SCA
from vuln_scanner.tools.xeol import XeolTool
from vuln_scanner.tools.retire_js import RetireJSTool
from vuln_scanner.tools.yarn_audit import YarnAuditTool
from vuln_scanner.tools.bundler_audit import BundlerAuditTool
from vuln_scanner.tools.cargo_audit import CargoAuditTool
from vuln_scanner.tools.nancy import NancyTool
from vuln_scanner.tools.cyclonedx import CycloneDXTool
from vuln_scanner.tools.license_finder import LicenseFinderTool
# Secrets
from vuln_scanner.tools.whispers import WhispersTool
from vuln_scanner.tools.rusty_hog import RustyHogTool
from vuln_scanner.tools.gitrob import GitrobTool
from vuln_scanner.tools.gitjacker import GitjackerTool
from vuln_scanner.tools.gato import GatoTool
from vuln_scanner.tools.zizmor import ZizmorTool
# IaC / Cloud
from vuln_scanner.tools.kics import KICSTool
from vuln_scanner.tools.regula import RegulaToool
from vuln_scanner.tools.cfn_nag import CfnNagTool
from vuln_scanner.tools.scoutsuite import ScoutSuiteTool
from vuln_scanner.tools.cloudsploit import CloudsploitTool
from vuln_scanner.tools.threagile import ThreagileToool
from vuln_scanner.tools.cloudfox import CloudfoxTool
from vuln_scanner.tools.roadrecon import ROADreconTool
from vuln_scanner.tools.s3scanner import S3ScannerTool
from vuln_scanner.tools.awsbucketdump import AWSBucketDumpTool
from vuln_scanner.tools.cloudscraper_tool import CloudScraperTool
# System
from vuln_scanner.tools.openscap import OpenSCAPTool
from vuln_scanner.tools.clamav import ClamAVTool
from vuln_scanner.tools.yara_tool import YARATool
from vuln_scanner.tools.rkhunter import RkhunterTool
from vuln_scanner.tools.chkrootkit import ChkrootkitTool
from vuln_scanner.tools.vuls import VulsTool
from vuln_scanner.tools.wappalyzer import WappalyzerTool
# Mobile
from vuln_scanner.tools.mobsf import MobSFTool
from vuln_scanner.tools.androbugs import AndroBugsTool
from vuln_scanner.tools.qark import QARKTool
from vuln_scanner.tools.apkid import APKiDTool
from vuln_scanner.tools.apkleaks import APKLeaksTool
from vuln_scanner.tools.androwarn import AndrowarnTool
from vuln_scanner.tools.quark_engine import QuarkEngineTool
from vuln_scanner.tools.mvt import MVTTool
# Subdomain takeover
from vuln_scanner.tools.subover import SubOverTool
from vuln_scanner.tools.autosub_takeover import AutoSubTakeoverTool
from vuln_scanner.tools.second_order import SecondOrderTool
# Binary
from vuln_scanner.tools.binwalk import BinwalkTool
# OSINT
from vuln_scanner.tools.spiderfoot import SpiderFootTool
from vuln_scanner.tools.photon import PhotonTool
from vuln_scanner.tools.reconftw import ReconFTWTool
from vuln_scanner.tools.waymore import WaymoreTool
from vuln_scanner.tools.xnlinkfinder import XnLinkFinderTool
from vuln_scanner.tools.hakip2host import HakIp2HostTool
from vuln_scanner.tools.witnessme import WitnessMeTool
# Generic
from vuln_scanner.tools.sarif_importer import SARIFImporterTool
from vuln_scanner.tools.garak import GarakTool

TOOL_REGISTRY: dict[str, type[AbstractTool]] = {
    # Web application scanning
    "nmap":               NmapTool,
    "nuclei":             NucleiTool,
    "nikto":              NiktoTool,
    "wapiti":             WapitiTool,
    "wpscan":             WPScanTool,
    "zap":                ZAPTool,
    "gowitness":          GowitnesssTool,
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
    # Subdomain takeover
    "subjack":            SubjackTool,
    "subzy":              SubzyTool,
    "dnsreaper":          DnsReaperTool,
    # Web (additional)
    "jwt-tool":           JwtToolTool,
    "tplmap":             TplmapTool,
    "nomore403":          Nomore403Tool,
    "h2csmuggler":        H2cSmugglerTool,
    # Secrets / exposed .git
    "git-dumper":         GitDumperTool,
    # Cloud / K8s
    "kubescape":          KubescapeTool,
    "kube-hunter":        KubeHunterTool,
    # Recon
    "bbot":               BbotTool,
    # Network / brute force
    "hydra":              HydraTool,
    # System
    "lynis":              LynisTool,
    # Binary analysis
    "checksec":           ChecksecTool,
    # ── New tools ──────────────────────────────────────────────────────────────
    # Web
    "dirsearch":          DirsearchTool,
    "kxss":               KxssTool,
    "crlfuite":           CRLFsuiteTool,
    "ssrfmap":            SSRFmapTool,
    "oralyzer":           OralyzerTool,
    "sstimap":            SSTImapTool,
    "corsy":              CorsyTool,
    "ghauri":             GhauriTool,
    "xsrfprobe":          XSRFProbeTool,
    "joomscan":           JoomscanTool,
    "cmsmap":             CMSmapTool,
    "aemhacker":          AEMHackerTool,
    "whatwaf":            WhatWafTool,
    "jaeles":             JaelesTool,
    "blackwidow":         BlackWidowTool,
    "jsparser":           JSParserTool,
    "parameth":           ParamethTool,
    # Network
    "medusa":             MedusaTool,
    "findomain":          FindomainTool,
    "massdns":            MassDNSTool,
    "shuffledns":         ShuffleDNSTool,
    "assetfinder":        AssetfinderTool,
    "vhostscan":          VHostScanTool,
    "subdominator":       SubdominatorTool,
    "zmap":               ZmapTool,
    "gotator":            GotatorTool,
    "ripgen":             RipgenTool,
    "dnsgen":             DNSgenTool,
    "gauplus":            GauplusTool,
    "haktrails":          HaktrailsTool,
    "csprecon":           CspreconTool,
    "github-subdomains":  GithubSubdomainsTool,
    "chaos-client":       ChaosClientTool,
    "knockpy":            KnockpyTool,
    # Container / K8s
    "syft":               SyftTool,
    "dockle":             DockleTool,
    "docker-bench":       DockerBenchTool,
    "kubeaudit":          KubeauditTool,
    "kube-score":         KubeScoreTool,
    "kube-linter":        KubeLinterTool,
    "popeye":             PopeyeTool,
    "dive":               DiveTool,
    # SAST
    "codeql":             CodeQLTool,
    "spotbugs":           SpotBugsTool,
    "pmd":                PMDTool,
    "infer":              InferTool,
    "cppcheck":           CppcheckTool,
    "devskim":            DevSkimTool,
    "eslint":             ESLintTool,
    "psalm":              PsalmTool,
    "progpilot":          ProgPilotTool,
    "rubocop":            RuboCopTool,
    "codechecker":        CodeCheckerTool,
    "dawnscanner":        DawnScannerTool,
    "joern":              JoernTool,
    "insider":            InsiderTool,
    "weggli":             WeggliTool,
    # SCA
    "xeol":               XeolTool,
    "retire-js":          RetireJSTool,
    "yarn-audit":         YarnAuditTool,
    "bundler-audit":      BundlerAuditTool,
    "cargo-audit":        CargoAuditTool,
    "nancy":              NancyTool,
    "cyclonedx":          CycloneDXTool,
    "license-finder":     LicenseFinderTool,
    # Secrets
    "whispers":           WhispersTool,
    "rusty-hog":          RustyHogTool,
    "gitrob":             GitrobTool,
    "gitjacker":          GitjackerTool,
    "gato":               GatoTool,
    "zizmor":             ZizmorTool,
    # IaC / Cloud
    "kics":               KICSTool,
    "regula":             RegulaToool,
    "cfn-nag":            CfnNagTool,
    "scoutsuite":         ScoutSuiteTool,
    "cloudsploit":        CloudsploitTool,
    "threagile":          ThreagileToool,
    "cloudfox":           CloudfoxTool,
    "roadrecon":          ROADreconTool,
    "s3scanner":          S3ScannerTool,
    "awsbucketdump":      AWSBucketDumpTool,
    "cloudscraper":       CloudScraperTool,
    # System
    "openscap":           OpenSCAPTool,
    "clamav":             ClamAVTool,
    "yara":               YARATool,
    "rkhunter":           RkhunterTool,
    "chkrootkit":         ChkrootkitTool,
    "vuls":               VulsTool,
    "wappalyzer":         WappalyzerTool,
    # Mobile
    "mobsf":              MobSFTool,
    "androbugs":          AndroBugsTool,
    "qark":               QARKTool,
    "apkid":              APKiDTool,
    "apkleaks":           APKLeaksTool,
    "androwarn":          AndrowarnTool,
    "quark-engine":       QuarkEngineTool,
    "mvt":                MVTTool,
    # Subdomain takeover
    "subover":            SubOverTool,
    "autosub-takeover":   AutoSubTakeoverTool,
    "second-order":       SecondOrderTool,
    # Binary
    "binwalk":            BinwalkTool,
    # OSINT
    "spiderfoot":         SpiderFootTool,
    "photon":             PhotonTool,
    "reconftw":           ReconFTWTool,
    "waymore":            WaymoreTool,
    "xnlinkfinder":       XnLinkFinderTool,
    "hakip2host":         HakIp2HostTool,
    "witnessme":          WitnessMeTool,
    # Generic
    "sarif-import":       SARIFImporterTool,
    "garak":              GarakTool,
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
    "GowitnesssTool",
    "HydraTool",
    "LynisTool",
    "SubjackTool",
    "SubzyTool",
    "DnsReaperTool",
    "JwtToolTool",
    "TplmapTool",
    "GitDumperTool",
    "KubescapeTool",
    "KubeHunterTool",
    "BbotTool",
    "Nomore403Tool",
    "ChecksecTool",
    "H2cSmugglerTool",
    # Web
    "DirsearchTool", "KxssTool", "CRLFsuiteTool", "SSRFmapTool", "OralyzerTool",
    "SSTImapTool", "CorsyTool", "GhauriTool", "XSRFProbeTool", "JoomscanTool",
    "CMSmapTool", "AEMHackerTool", "WhatWafTool", "JaelesTool", "BlackWidowTool",
    "JSParserTool", "ParamethTool",
    # Network
    "MedusaTool", "FindomainTool", "MassDNSTool", "ShuffleDNSTool", "AssetfinderTool",
    "VHostScanTool", "SubdominatorTool", "ZmapTool", "GotatorTool", "RipgenTool",
    "DNSgenTool", "GauplusTool", "HaktrailsTool", "CspreconTool", "GithubSubdomainsTool",
    "ChaosClientTool", "KnockpyTool",
    # Container / K8s
    "SyftTool", "DockleTool", "DockerBenchTool", "KubeauditTool", "KubeScoreTool",
    "KubeLinterTool", "PopeyeTool", "DiveTool",
    # SAST
    "CodeQLTool", "SpotBugsTool", "PMDTool", "InferTool", "CppcheckTool",
    "DevSkimTool", "ESLintTool", "PsalmTool", "ProgPilotTool", "RuboCopTool",
    "CodeCheckerTool", "DawnScannerTool", "JoernTool", "InsiderTool", "WeggliTool",
    # SCA
    "XeolTool", "RetireJSTool", "YarnAuditTool", "BundlerAuditTool", "CargoAuditTool",
    "NancyTool", "CycloneDXTool", "LicenseFinderTool",
    # Secrets
    "WhispersTool", "RustyHogTool", "GitrobTool", "GitjackerTool", "GatoTool", "ZizmorTool",
    # IaC / Cloud
    "KICSTool", "RegulaToool", "CfnNagTool", "ScoutSuiteTool", "CloudsploitTool",
    "ThreagileToool", "CloudfoxTool", "ROADreconTool", "S3ScannerTool",
    "AWSBucketDumpTool", "CloudScraperTool",
    # System
    "OpenSCAPTool", "ClamAVTool", "YARATool", "RkhunterTool", "ChkrootkitTool",
    "VulsTool", "WappalyzerTool",
    # Mobile
    "MobSFTool", "AndroBugsTool", "QARKTool", "APKiDTool", "APKLeaksTool",
    "AndrowarnTool", "QuarkEngineTool", "MVTTool",
    # Subdomain takeover
    "SubOverTool", "AutoSubTakeoverTool", "SecondOrderTool",
    # Binary
    "BinwalkTool",
    # OSINT
    "SpiderFootTool", "PhotonTool", "ReconFTWTool", "WaymoreTool",
    "XnLinkFinderTool", "HakIp2HostTool", "WitnessMeTool",
    # Generic
    "SARIFImporterTool", "GarakTool",
    "TOOL_REGISTRY",
]
