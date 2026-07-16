# vuln-scanner

An automated vulnerability assessment platform that orchestrates **65 open-source security tools**, aggregates and deduplicates findings, runs an optional **OpenAI-compatible LLM analysis layer** for triage, clustering, and remediation, generates **proof-of-concept scripts**, and produces professional **Markdown, HTML, and JSON reports** — all from a single BlackArch Linux Docker image.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Tools](#tools)
3. [Target Type Gating](#target-type-gating)
4. [Scan Modes](#scan-modes)
5. [LLM Analysis](#llm-analysis)
6. [PoC Generation and Execution](#poc-generation-and-execution)
7. [Report Formats](#report-formats)
8. [Quick Start](#quick-start)
9. [Configuration](#configuration)
10. [Environment Variables](#environment-variables)
11. [Project Structure](#project-structure)
12. [Adding a New Tool](#adding-a-new-tool)
13. [Development](#development)
14. [DefectDojo Integration](#defectdojo-integration)

---

## Architecture

```
config.toml / env vars / CLI args
             ↓
       AppConfig (pydantic, 3-layer merge: TOML < env < CLI)
             ↓
     ScanOrchestrator
      • classify_target() → TargetType
      • tool.applies_to(target) — skips mismatched pairs
      • ThreadPoolExecutor — parallel (tool × target) tasks
             ↓
      ScanResult[]  →  Assessment
             ↓
    LLMAnalyzer (optional)
      • Pass 1: triage + PoC design  (threaded, per result)
      • Pass 2: PoC generation       (PocGenerator, host-safe)
      • Pass 3: mitigation           (evidence-informed)
      • Pass 4: clustering + exec summary
             ↓
      PocRunner (container-only, VS_IN_CONTAINER=1 guard)
             ↓
    ┌────────┬────────┬────────┐
    │   .md  │  .html │  .json │   (all formats written in parallel)
    └────────┴────────┴────────┘
             ↓
        DefectDojo (optional)
```

All scanning tools and PoC execution run inside a **BlackArch Linux** Docker container — nothing is installed on the host.

---

## Tools

65 tools organized by category. Each tool declares the target types it supports; the orchestrator skips incompatible pairings automatically.

### Network & Port Scanning
| Tool | Notes |
|------|-------|
| `nmap` | Full port scan with service/version detection |
| `rustscan` | Fast port scanner, feeds into nmap |
| `masscan` | High-speed TCP/UDP scanner |
| `naabu` | Port scanner with service detection |
| `netdiscover` | ARP-based host discovery |

### Web Application
| Tool | Notes |
|------|-------|
| `nuclei` | Template-based vulnerability scanner |
| `nikto` | Web server misconfiguration scanner |
| `wapiti` | Black-box web vulnerability scanner |
| `ffuf` | Fast web fuzzer (dirs, params, headers) |
| `feroxbuster` | Content discovery with recursion |
| `gobuster` | URI/DNS/vhost brute-forcer |
| `wfuzz` | Web application fuzzer |
| `dalfox` | XSS scanner with parameter analysis |
| `xsstrike` | Advanced XSS detection engine |
| `commix` | Command injection exploiter |
| `sqlmap` | Automated SQL injection and takeover |
| `nosqlmap` | NoSQL injection scanner |
| `httpx` | HTTP probing and fingerprinting |
| `whatweb` | Web technology fingerprinter |
| `wafw00f` | WAF detection and fingerprinting |
| `wpscan` | WordPress vulnerability scanner |
| `acunetix` | Web vulnerability scanner (API-based) |
| `arachni` | Web application security scanner |
| `zap` | OWASP ZAP DAST scanner |
| `wapiti` | Black-box vulnerability scanner |
| `drheader` | HTTP security header analyser |
| `humble` | HTTP header security checker |
| `hakrawler` | Fast web crawler for URLs and endpoints |
| `katana` | Next-gen web crawling framework |
| `gau` | Known URL collector (AlienVault, WaybackMachine) |
| `jsluice` | JavaScript secrets and URL extractor |
| `corscanner` | CORS misconfiguration scanner |

### API & GraphQL
| Tool | Notes |
|------|-------|
| `kiterunner` | API route discovery with kite files |
| `graphql_cop` | GraphQL security auditor |
| `restler` | Stateful REST API fuzzer |
| `apifuzzer` | OpenAPI/Swagger-based fuzzer |
| `cherrybomb` | OpenAPI spec security linter |
| `arjun` | HTTP parameter discovery |
| `paramspider` | Parameter mining from wayback/sources |

### DNS & Reconnaissance
| Tool | Notes |
|------|-------|
| `amass` | Subdomain enumeration (passive + active) |
| `subfinder` | Fast passive subdomain enumeration |
| `dnsx` | DNS resolver and probe toolkit |
| `dnsrecon` | DNS enumeration and zone transfer |
| `fierce` | DNS reconnaissance and host discovery |
| `theharvester` | OSINT: emails, names, hosts, subdomains |

### TLS / SSL
| Tool | Notes |
|------|-------|
| `testssl` | TLS configuration and cipher suite audit |
| `sslyze` | TLS scanner (cipher suites, Heartbleed, ROBOT) |
| `sslscan` | SSL/TLS service scanner |
| `tlsx` | Fast TLS probing |
| `tls_attacker` | TLS protocol attack tool |
| `ssh_audit` | SSH configuration and algorithm auditor |

### SMB & Network Services
| Tool | Notes |
|------|-------|
| `smbmap` | SMB share enumeration and permissions |
| `enum4linux` | SMB/NetBIOS enumeration |
| `crackmapexec` | Active Directory and SMB assessment |
| `openvas` | OpenVAS vulnerability scanner |

### SAST & Code Analysis
| Tool | Notes |
|------|-------|
| `bandit` | Python SAST — common security anti-patterns |
| `semgrep` | Multi-language SAST with community rules |
| `gosec` | Go security checker |
| `dependency_check` | OWASP dependency vulnerability scanner |
| `pip_audit` | Python package vulnerability checker |

### Secrets Detection
| Tool | Notes |
|------|-------|
| `gitleaks` | Git history secret scanner |
| `trufflehog` | Deep entropy-based secret finder |
| `secretfinder` | Secrets in JS files and endpoints |

### IaC & Configuration
| Tool | Notes |
|------|-------|
| `checkov` | Terraform/K8s/Dockerfile IaC scanner |
| `tfsec` | Terraform static analysis |

### Container & Supply Chain
| Tool | Notes |
|------|-------|
| `trivy` | Container image + filesystem vulnerability scanner |
| `grype` | Container and package vulnerability matcher |

---

## Target Type Gating

The orchestrator classifies each target into one or more types and only runs tools that declare support for that type. This eliminates noise from e.g. SMB tools running against web URLs.

| Type | Example | Tools that match |
|------|---------|-----------------|
| `HOST` | `example.com` | DNS, SSL, web, SMB tools |
| `IP` | `10.0.0.1` | Network, port, SMB tools |
| `CIDR` | `10.0.0.0/24` | Network scanners |
| `URL` | `https://app.example.com` | Web, API, SSL tools |
| `PATH` | `/src/myapp` | SAST, secrets, IaC tools |
| `REPO` | `https://github.com/org/repo` | Secrets, SAST tools |
| `IMAGE` | `myapp:latest` | Container scanners |

Classification is automatic — just pass the target string; the scanner figures out the type.

---

## Scan Modes

| Mode | Description |
|------|-------------|
| `paranoid` | Maximum stealth — passive probing, minimal footprint |
| `passive` | No active attacks — enumeration and banner grabbing only **(default)** |
| `active` | Standard vulnerability checks enabled |
| `aggressive` | Full scan: all templates, brute-force, fast timing |

---

## LLM Analysis

When an API key is present, the LLM layer activates automatically. It performs four passes over the scan results:

| Pass | Name | What it does |
|------|------|-------------|
| 1 | **Triage** | Assigns CWE, confidence, false-positive flag, exploitability summary, and designs a PoC for each finding |
| 2 | **PoC generation** | Writes self-contained Python/Bash scripts that confirm the finding using tools already in the container |
| 3 | **Mitigation** | Produces concrete short-term mitigations and permanent remediations, optionally informed by PoC evidence |
| 4 | **Clustering** | Groups findings by root cause, writes shared remediations, and produces an executive summary |

### Provider configuration

The LLM client is OpenAI-API-compatible — works with OpenAI, Azure OpenAI, Ollama, vLLM, LM Studio, OpenRouter, and any other compatible endpoint.

```toml
[llm]
enabled   = "auto"          # "auto" | true | false  (auto = on when api_key present)
api_key   = ""              # or set OPENAI_API_KEY env var
base_url  = ""              # leave empty for OpenAI; set for Ollama/vLLM/etc.
model     = "gpt-4o"        # REQUIRED when LLM is active — no default

# Sampling parameters (all OpenAI-compatible)
temperature = 0.2
top_p       = 0.95
max_tokens  = 4096
# top_k and other non-standard params go in extra_body:
# [llm.extra_body]
# top_k = 40
```

**Ollama example:**
```toml
[llm]
base_url = "http://localhost:11434/v1"
api_key  = "ollama"
model    = "llama3.2"
```

**vLLM example:**
```toml
[llm]
base_url = "http://localhost:8000/v1"
api_key  = "token-abc123"
model    = "meta-llama/Meta-Llama-3-8B-Instruct"
```

### Feature matrix

Each LLM capability is a named feature, toggleable globally and overridable per tool or per category.

| Feature | Default | Description |
|---------|:-------:|-------------|
| `logs_analysis` | on | Feed tool's raw output to the LLM |
| `enrich` | on | CWE / confidence / false-positive / exploitability triage |
| `classify` | on | Classify finding type and risk |
| `cluster` | on | Group findings by root cause |
| `mitigation` | on | Generate mitigation and remediation |
| `generate_poc` | on | Write PoC scripts as report assets |
| `execute_poc` | **off** | Run PoCs in-container *(requires `VS_IN_CONTAINER=1`)* |
| `false_positive_filter` | on | Suppress likely false positives from the report |

**Global feature config:**
```toml
[llm.features]
generate_poc = true
execute_poc  = false   # enable only inside Docker

# Per-tool override — disable PoC for bandit (SAST, no runtime target)
[llm.features.tool.bandit]
generate_poc = false

# Per-category override — disable log analysis for noisy crawlers
[llm.features.category.web]
logs_analysis = false
```

**Feature precedence:** `tool override > category override > global`

### Custom prompts

All LLM prompts are overridable:

```toml
[llm.prompts]
enrich_system    = "You are a senior penetration tester..."
mitigation_user  = "Write remediation steps for: {title}..."
# Available placeholders: {title} {severity} {description} {cwe}
#   {exploitability} {tool} {target} {cves} {raw_output}
```

### Scope filters

```toml
[llm]
include_tools      = []          # empty = all tools
exclude_tools      = ["hakrawler", "gau"]
include_categories = []
exclude_categories = ["dns"]
```

---

## PoC Generation and Execution

### Generation (always host-safe)

The LLM writes self-contained Python and/or Bash scripts per finding. Scripts use tools already in the BlackArch image (`curl`, `sqlmap`, `nuclei`, `dalfox`, etc.) and are written to `<report>_assets/poc/`. Generation never executes code — it only writes files.

```toml
[llm.poc]
languages        = ["python", "bash"]
only_severities  = ["critical", "high", "medium"]
max_pocs         = 20
allow_git_clone  = false   # permit cloning official exploit PoCs from GitHub
```

### Execution (container-only)

PoC execution is gated behind two independent guards:

1. `execute_poc = true` in `[llm.features]`
2. `VS_IN_CONTAINER=1` environment variable (baked into the Docker image)

The runner refuses silently if either guard is missing, so it **cannot execute on the host**. A static denylist rejects scripts containing destructive patterns (`rm -rf /`, `mkfs.`, fork bombs, etc.) before execution.

```bash
# Enable PoC execution inside the container
VS_LLM_FEATURE_EXECUTE_POC=true docker compose ... run --rm scanner ...
```

---

## Report Formats

Three formats are generated in parallel. Select any combination:

```toml
[report]
formats    = ["markdown", "html", "json"]
output_dir = "./reports"
```

Or via CLI: `--formats markdown html json`

### Markdown (`.md`)

Professional structured report following industry pentest conventions:

1. **Executive Summary** — prose for management
2. **Scope and Methodology** — target list, tools used, scan config
3. **Severity Rating Guide** — CVSS ranges
4. **Findings Overview** — risk distribution matrix + per-target breakdown
5. **Vulnerability Clusters** — root-cause groupings (LLM-generated)
6. **Detailed Findings** — per finding: ID, severity, affected system, description, business impact, analyst note, mitigation, permanent remediation, PoC references
7. **Appendix A** — scan errors
8. **Appendix B** — PoC asset index

Findings from multiple tools reporting the same issue on the same target are deduplicated into a single entry showing all contributing tools.

### HTML (`.html`)

Self-contained single-file report (no external dependencies) with:
- Light/dark theme toggle
- Severity-colour-coded finding cards
- Collapsible cluster sections
- Stats grid and executive summary hero

### JSON (`.json`)

Full structured dump of the `Assessment` model — findings, LLM enrichment, clusters, stats, PoC records. Suitable for CI/CD pipeline ingestion and downstream tooling.

---

## Quick Start

The `poc.sh` script starts DefectDojo, three vulnerable targets, and the scanner in one command.

**Prerequisites:** `docker`, `docker compose` plugin, `curl`, `python3`

```bash
./poc.sh
```

| Step | Action |
|------|--------|
| 1 | Checks prerequisites |
| 2 | Loads `.env` (copies from `.env.example` if missing) |
| 3 | Starts DefectDojo stack |
| 4 | Waits for DefectDojo API to be ready |
| 5 | Obtains API token via admin credentials |
| 6 | Starts vulnerable target containers |
| 7 | Waits for each target to be reachable |
| 8 | Builds the scanner Docker image |
| 9 | Runs the scanner, generates reports, pushes to DefectDojo |
| 10 | Prints summary with URLs and teardown instructions |

**With LLM analysis:**
```bash
# Copy the example env and add your key
cp .env.example .env
# Edit .env: set OPENAI_API_KEY and VS_LLM_MODEL
./poc.sh
```

**Override scan mode:**
```bash
SCAN_MODE=active ./poc.sh
```

**Teardown:**
```bash
docker compose down -v
docker compose -f docker-compose.target.yaml down -v
```

---

## Vulnerable Targets

| App | URL | Description |
|-----|-----|-------------|
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | http://localhost:3000 | Modern Node.js app covering OWASP Top 10 |
| [DVWA](https://github.com/digininja/DVWA) | http://localhost:4280 | Classic PHP/MySQL vulnerable app |
| [WebGoat](https://owasp.org/www-project-webgoat/) | http://localhost:8888/WebGoat | Java/Spring intentionally insecure app |

---

## Configuration

Copy the annotated template:

```bash
cp config.example.toml config.toml
```

**Full reference:**

```toml
[scan]
targets    = ["192.168.1.1", "https://app.example.com", "/src/myapp"]
mode       = "passive"   # paranoid | passive | active | aggressive
timeout    = 300         # per-tool timeout in seconds
rate_limit = null        # requests/sec; null = no limit

[tools]
exclude = ["nikto"]      # skip specific tools by name

[categories]
include = ["web", "ssl"] # limit to these categories; empty = all

[report]
formats    = ["markdown", "html", "json"]
output_dir = "./reports"

[defectdojo]
url             = "http://localhost:8080"
api_key         = ""
product_name    = "My Product"
engagement_name = "Automated Scan"

# ── LLM Analysis ─────────────────────────────────────────────────────────────

[llm]
enabled     = "auto"     # "auto" | true | false
api_key     = ""         # or OPENAI_API_KEY env var
base_url    = ""         # leave empty for OpenAI
model       = ""         # required when active, e.g. "gpt-4o" or "llama3.2"
temperature = 0.2
top_p       = 0.95
max_tokens  = 4096
# extra_body = { top_k = 40 }   # for Ollama/vLLM top_k support

exclude_tools      = []
exclude_categories = []

[llm.features]
logs_analysis      = true
enrich             = true
classify           = true
cluster            = true
mitigation         = true
generate_poc       = true
execute_poc        = false  # container-only; set VS_LLM_FEATURE_EXECUTE_POC=true
false_positive_filter = true

# Per-tool feature overrides (tool > category > global precedence)
[llm.features.tool.bandit]
generate_poc = false

[llm.features.category.dns]
logs_analysis = false

[llm.poc]
languages       = ["python", "bash"]
only_severities = ["critical", "high", "medium"]
max_pocs        = 20
allow_git_clone = false
```

**Config merge precedence:** `CLI > env vars > config.toml > defaults`

---

## Environment Variables

### Core

| Variable | CLI flag | Description |
|----------|----------|-------------|
| `VS_TARGETS` | `--targets` | Space-separated target list |
| `VS_MODE` | `--mode` | Scan mode |
| `VS_TIMEOUT` | `--timeout` | Per-tool timeout (seconds) |
| `VS_RATE_LIMIT` | `--rate-limit` | Rate limit (req/s) |
| `VS_MAX_CONCURRENT` | `--max-concurrent` | Parallel tool slots |
| `VS_INCLUDE_TOOLS` | `--include-tools` | Whitelist tools by name |
| `VS_EXCLUDE_TOOLS` | `--exclude-tools` | Blacklist tools by name |
| `VS_INCLUDE_CATEGORIES` | `--include-categories` | Whitelist categories |
| `VS_EXCLUDE_CATEGORIES` | `--exclude-categories` | Blacklist categories |
| `VS_OUTPUT_DIR` | `--output-dir` | Report output directory |

### Reports

| Variable | CLI flag | Description |
|----------|----------|-------------|
| `VS_FORMATS` | `--formats` | Report formats: `markdown html json` |

### LLM

| Variable | CLI flag | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | — | API key (standard env var, used as fallback) |
| `OPENAI_BASE_URL` | — | Base URL fallback (for non-OpenAI endpoints) |
| `VS_LLM_ENABLED` | `--no-llm` | `auto` \| `true` \| `false` |
| `VS_LLM_MODEL` | `--llm-model` | Model name (required when active) |
| `VS_LLM_TEMPERATURE` | — | Sampling temperature |
| `VS_LLM_MAX_TOKENS` | — | Max output tokens |
| `VS_LLM_FEATURE_<NAME>` | `--llm-feature NAME=on` | Global feature toggle, e.g. `VS_LLM_FEATURE_GENERATE_POC=false` |
| `VS_LLM_FEATURE_EXECUTE_POC` | `--llm-poc-execute` | Enable PoC execution (container-only) |

### DefectDojo

| Variable | CLI flag | Description |
|----------|----------|-------------|
| `VS_DEFECTDOJO_URL` | `--defectdojo-url` | DefectDojo base URL |
| `VS_DEFECTDOJO_API_KEY` | `--defectdojo-api-key` | API token |
| `VS_DEFECTDOJO_PRODUCT` | — | Product name |
| `VS_DEFECTDOJO_ENGAGEMENT` | — | Engagement name |

---

## Project Structure

```
vuln_scanner/
├── config/
│   ├── models.py        # AppConfig, AppLLMConfig, ReportConfig (pydantic)
│   └── loader.py        # 3-layer merge: TOML + env (VS_*) + CLI
│
├── tools/
│   ├── enums.py         # Severity, Confidence, ScanStatus, ScanMode, TargetType
│   ├── models.py        # Finding, ScanInput, ScanResult (pydantic)
│   ├── target.py        # classify_target() — maps target string to TargetType set
│   ├── abstract.py      # AbstractTool ABC + subprocess execution helpers
│   ├── __init__.py      # TOOL_REGISTRY (65 tools)
│   └── <tool>.py        # One file per tool (65 total)
│
├── llm/
│   ├── models.py        # LLMConfig, LLMFeatures, PocConfig (pydantic)
│   ├── features.py      # resolve_features() — tool > category > global merge
│   ├── client.py        # LLMClient — thin openai SDK wrapper
│   ├── analyzer.py      # LLMAnalyzer — 4-pass analysis pipeline
│   └── prompts.py       # Default prompt templates (all overridable)
│
├── poc/
│   ├── models.py        # Poc, PocVerdict
│   ├── generator.py     # PocGenerator — writes scripts, never executes (host-safe)
│   └── runner.py        # PocRunner — executes scripts (VS_IN_CONTAINER guard)
│
├── reports/
│   ├── base.py          # AbstractReporter
│   ├── markdown.py      # Professional structured Markdown report
│   ├── html.py          # Self-contained HTML with light/dark theme
│   └── json_reporter.py # Full Assessment JSON dump
│
├── defectdojo/
│   └── client.py        # DefectDojoClient — push findings via REST API
│
├── model.py             # Assessment, Cluster, AssessmentStats
└── orchestrator.py      # ScanOrchestrator — type-gated, concurrent execution

main.py                  # Entry point
config.example.toml      # Fully documented configuration template
.env.example             # Environment variable reference
Dockerfile               # BlackArch-based image; bakes VS_IN_CONTAINER=1
docker-compose.yml                # DefectDojo stack
docker-compose.scanner.yml        # Scanner service
docker-compose.target.yaml        # Vulnerable test targets (Juice Shop, DVWA, WebGoat)
poc.sh                            # End-to-end quick-start script
```

---

## Adding a New Tool

1. Create `vuln_scanner/tools/mytool.py`:

```python
from vuln_scanner.tools.abstract import AbstractTool
from vuln_scanner.tools.enums import Severity, TargetType
from vuln_scanner.tools.models import Finding, ScanInput

class MyTool(AbstractTool):
    name: str = "mytool"
    category: str = "web"
    # Declare which target types this tool supports.
    # The orchestrator skips mismatched (tool, target) pairs automatically.
    applicable_targets: frozenset[TargetType] = frozenset({TargetType.URL, TargetType.HOST})

    def build_command(self, target: str, scan_input: ScanInput) -> list[str]:
        return ["mytool", "--target", target]

    def parse_output(self, raw: str, target: str) -> list[Finding]:
        findings = []
        for line in raw.splitlines():
            if "VULN" in line:
                findings.append(Finding(
                    title="Example finding",
                    severity=Severity.HIGH,
                    description=line,
                    tool=self.name,
                    target=target,
                ))
        return findings
```

2. Register it in `vuln_scanner/tools/__init__.py`:

```python
from vuln_scanner.tools.mytool import MyTool

TOOL_REGISTRY: dict[str, type[AbstractTool]] = {
    ...
    "mytool": MyTool,
}
```

3. Add the binary to `Dockerfile`:

```dockerfile
RUN pacman -Sy --noconfirm mytool
```

**Tips:**
- For tools that write to a file instead of stdout, use `OUTPUT_FILE_SENTINEL` in `build_command()` and override `run()` to call `self._run_with_tempfile()`.
- Tools with `applicable_targets = frozenset(TargetType)` (the default) run against all target types — use this only for genuinely universal tools.
- Binary not found → `ScanStatus.SKIPPED` (hidden from report). Tool error → `ScanStatus.FAILED` (shown in Appendix A).

---

## Development

```bash
# Install with dev dependencies
uv sync

# Run tests (host-safe only — no real tool execution)
uv run pytest tests/ -v

# Lint
uv run ruff check .
uv run ruff format .
```

**Test categories:**
- `tests/test_config.py` — config merge and validation
- `tests/test_target_typing.py` — `classify_target()` and `applies_to()`
- `tests/test_orchestrator_gating.py` — type-gating with mock tools
- `tests/test_llm.py` — LLM features, mocked client, PoC runner container guard
- `tests/test_reports.py` — all three reporters (Markdown, HTML, JSON)
- `tests/test_nmap.py` — nmap output parser

**Safety rule:** never run real scanning tools on the host. All tool execution happens inside the Docker container against the isolated target containers. The `PocRunner` enforces this — it checks `VS_IN_CONTAINER=1` before executing any PoC script, and the Docker image bakes this variable in.

---

## DefectDojo Integration

Findings are pushed automatically when `api_key` and `product_name` are configured.

**Get your API key:**
1. Open DefectDojo at http://localhost:8080
2. Log in (default: `admin` / `admin`)
3. Go to **Profile → API v2 Key**

**Manual push:**
```bash
VS_DEFECTDOJO_API_KEY=your-key \
VS_DEFECTDOJO_PRODUCT="My App" \
uv run vuln-scanner --targets 192.168.1.1
```
