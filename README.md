# vuln-scanner

Automated vulnerability assessment scanner that orchestrates open-source security tools, aggregates findings, and pushes results to [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) for tracking and reporting.

---

## Architecture

```
config.toml / env vars / CLI args
         ↓
   ScanOrchestrator
         ↓
  ┌──────┴──────┐
  │  Tool(s)    │  (Nmap, Nikto, Nuclei, testssl.sh, ...)
  └──────┬──────┘
         ↓
   ScanResult[]
    ↙         ↘
Markdown      DefectDojo
 Report         API
```

All tools run inside a **BlackArch Linux** Docker container — no host installation required.

---

## Scan Modes

| Mode | Description | Nmap timing |
|---|---|---|
| `paranoid` | Maximum stealth, evades IDS | T0 |
| `passive` | No active probing, enumeration only | T1 (default) |
| `active` | Standard port/service scan + vuln checks | T3 |
| `aggressive` | Full scan: OS detection, all templates | T4 |

---

## Quick Start (PoC)

The `poc.sh` script starts DefectDojo, three vulnerable targets, and the scanner end-to-end in one command.

**Prerequisites:** `docker`, `docker compose` plugin, `curl`, `python3`

```bash
./poc.sh
```

**What it does:**

| Step | Action |
|---|---|
| 1 | Checks prerequisites |
| 2 | Loads `.env` (copies from `.env.example` if missing) |
| 3 | Starts DefectDojo stack |
| 4 | Waits for DefectDojo nginx and API to be ready |
| 5 | Obtains an API token via admin credentials |
| 6 | Starts vulnerable target containers |
| 7 | Waits for each target to be reachable |
| 8 | Builds the scanner Docker image |
| 9 | Runs the scanner against all targets and pushes findings to DefectDojo |
| 10 | Prints a summary with URLs and teardown instructions |

**Override defaults without editing files:**

```bash
SCAN_MODE=aggressive DD_PRODUCT="MyProject" ./poc.sh
```

**Teardown:**

```bash
docker compose down -v
docker compose -f docker-compose.target.yaml down -v
```

---

## Vulnerable Targets

Started automatically by `poc.sh` via `docker-compose.target.yaml`.

| App | URL | Description |
|---|---|---|
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | http://localhost:3000 | Modern Node.js app covering OWASP Top 10 |
| [DVWA](https://github.com/digininja/DVWA) | http://localhost:4280 | Classic PHP/MySQL vulnerable app |
| [WebGoat](https://owasp.org/www-project-webgoat/) | http://localhost:8888/WebGoat | Java/Spring intentionally insecure app |

---

## Manual Usage

### Configuration

Copy and edit the example config:

```bash
cp config.example.toml config.toml
```

Key options in `config.toml`:

```toml
[scan]
targets = ["192.168.1.1", "10.0.0.0/24"]
mode    = "passive"   # paranoid | passive | active | aggressive
timeout = 300

[tools]
exclude = ["nikto"]   # skip specific tools

[report]
format     = "markdown"
output_dir = "./reports"

[defectdojo]
url             = "http://localhost:8080"
api_key         = "your-api-key-here"
product_name    = "My Product"
engagement_name = "Automated Scan"
```

All options can also be set via environment variables (`VS_*` prefix) or CLI flags — CLI > env > config file > defaults.

### Run locally

```bash
# Install dependencies
uv sync

# Scan a target
uv run vuln-scanner --targets 192.168.1.1 --mode active

# With a config file
uv run vuln-scanner --config config.toml

# Verbose output
uv run vuln-scanner --targets 192.168.1.1 -v

# Show all options
uv run vuln-scanner --help
```

### Run in Docker

```bash
# Start DefectDojo
docker compose up -d

# Start targets (optional)
docker compose -f docker-compose.target.yaml up -d

# Build and run the scanner
docker compose -f docker-compose.yml -f docker-compose.scanner.yml \
  run --rm scanner \
    --targets 192.168.1.1 \
    --mode active
```

---

## Environment Variables

| Variable | CLI equivalent | Description |
|---|---|---|
| `VS_TARGETS` | `--targets` | Space-separated list of targets |
| `VS_MODE` | `--mode` | Scan mode |
| `VS_TIMEOUT` | `--timeout` | Per-tool timeout (seconds) |
| `VS_MAX_CONCURRENT` | `--max-concurrent` | Parallel tool slots |
| `VS_INCLUDE_TOOLS` | `--include-tools` | Whitelist tools by name |
| `VS_EXCLUDE_TOOLS` | `--exclude-tools` | Blacklist tools by name |
| `VS_INCLUDE_CATEGORIES` | `--include-categories` | Whitelist categories |
| `VS_EXCLUDE_CATEGORIES` | `--exclude-categories` | Blacklist categories |
| `VS_REPORT_FORMAT` | `--format` | Report format (`markdown`) |
| `VS_OUTPUT_DIR` | `--output-dir` | Report output directory |
| `VS_DEFECTDOJO_URL` | `--defectdojo-url` | DefectDojo base URL |
| `VS_DEFECTDOJO_API_KEY` | `--defectdojo-api-key` | DefectDojo API token |
| `VS_DEFECTDOJO_PRODUCT` | — | DefectDojo product name |
| `VS_DEFECTDOJO_ENGAGEMENT` | — | DefectDojo engagement name |

---

## Project Structure

```
vuln_scanner/
├── config/
│   ├── models.py       # Pydantic config models (AppConfig, ScanMode, ...)
│   └── loader.py       # TOML + env + CLI merge logic
├── tools/
│   ├── base.py         # AbstractTool, Finding, ScanInput, ScanResult
│   └── nmap.py         # NmapTool (example implementation)
├── defectdojo/
│   └── client.py       # DefectDojoClient — push findings via REST API
├── reports/
│   ├── base.py         # AbstractReporter
│   └── markdown.py     # MarkdownReporter
└── orchestrator.py     # ScanOrchestrator — filters tools, runs scans concurrently

main.py                 # Entry point
config.example.toml     # Documented config template
Dockerfile              # BlackArch-based scanner image
docker-compose.yml                # Main compose entry (includes DefectDojo)
docker-compose.defectdojo.yml     # DefectDojo stack
docker-compose.scanner.yml        # Scanner service
docker-compose.target.yaml        # Vulnerable test targets
poc.sh                            # End-to-end PoC script
```

---

## Adding a New Tool

1. Create `vuln_scanner/tools/mytool.py` extending `AbstractTool`
2. Implement `build_command()` and `parse_output()`
3. Register it in `vuln_scanner/tools/__init__.py`:

```python
from vuln_scanner.tools.mytool import MyTool

TOOL_REGISTRY: dict[str, type[AbstractTool]] = {
    "nmap": NmapTool,
    "mytool": MyTool,   # ← add here
}
```

4. Add the tool binary to `Dockerfile` via `pacman -S`

---

## Development

```bash
# Install with dev dependencies
uv sync

# Run tests
uv run pytest tests/ -v

# Lint and format
uv run ruff check .
uv run ruff format .
```

---

## DefectDojo

Findings are pushed automatically if `api_key` and `product_name` are configured. To get your API key:

1. Open DefectDojo at http://localhost:8080
2. Log in (default: `admin` / `admin`)
3. Go to **Profile → API v2 Key**
