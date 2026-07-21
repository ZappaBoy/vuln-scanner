#!/usr/bin/env bash
# scanner.sh — Convenience wrapper for running vuln-scanner via Docker Compose.
# All scanner CLI flags are accepted and forwarded to the container entrypoint.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colours ──────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF

${BOLD}Usage:${NC}
  ./scanner.sh [OPTIONS] [-- SCANNER_ARGS...]

${BOLD}Options:${NC}
  -t, --targets HOST...       One or more scan targets (URL, IP, CIDR, path, image)
  -m, --mode MODE             Scan mode: passive | active | aggressive | paranoid
  -c, --config FILE           Config file to use (default: ./config.toml)
                              File is mounted into the container automatically.
  -f, --formats FMT           Report formats, comma-separated: markdown,html,json
                              (default from config; can repeat: -f markdown -f html)
      --no-llm                Disable LLM enrichment
      --llm-model MODEL       LLM model (e.g. gpt-4o, claude-3-5-sonnet-20241022)
      --llm-min-severity SEV  Minimum finding severity for LLM: info|low|medium|high|critical
      --include-tools TOOLS   Comma-separated list of tools to run
      --exclude-tools TOOLS   Comma-separated list of tools to skip
  -e, --env KEY=VALUE         Pass an extra environment variable to the container
  -b, --build                 Rebuild the Docker image before running
  -n, --no-defectdojo         Skip DefectDojo integration (no network required)
      --shell                 Open an interactive shell inside the container instead of scanning
  -h, --help                  Show this help

${BOLD}Anything after${NC} ${CYAN}--${NC} ${BOLD}is forwarded directly to the scanner entrypoint.${NC}

${BOLD}Examples:${NC}
  # Scan using ./config.toml
  ./scanner.sh

  # Quick scan with explicit targets and mode
  ./scanner.sh -t https://app.example.com 192.168.1.0/24 -m active

  # Use a custom config file
  ./scanner.sh -c /path/to/prod.toml

  # Enable LLM enrichment with a specific model
  ./scanner.sh -t https://app.example.com --llm-model gpt-4o

  # Full manual passthrough
  ./scanner.sh -- --targets https://t.example.com --mode aggressive --formats markdown html json

  # Rebuild image, then scan
  ./scanner.sh --build -t https://app.example.com -m active

  # Open a shell in the container (all tools, volumes, and env available)
  ./scanner.sh --shell
  ./scanner.sh --build --shell

EOF
}

# ── Arg parsing ───────────────────────────────────────────────────────────────
TARGETS=()
MODE=""
CONFIG_FILE=""
FORMATS=()
NO_LLM=0
LLM_MODEL=""
LLM_MIN_SEVERITY=""
INCLUDE_TOOLS=""
EXCLUDE_TOOLS=""
EXTRA_ENV=()
DO_BUILD=0
NO_DEFECTDOJO=0
SHELL_MODE=0
PASSTHROUGH=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--targets)
            shift
            while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                TARGETS+=("$1"); shift
            done ;;
        -m|--mode)            MODE="$2";             shift 2 ;;
        -c|--config)          CONFIG_FILE="$2";      shift 2 ;;
        -f|--formats)         FORMATS+=("$2");       shift 2 ;;
        --no-llm)             NO_LLM=1;              shift ;;
        --llm-model)          LLM_MODEL="$2";        shift 2 ;;
        --llm-min-severity)   LLM_MIN_SEVERITY="$2"; shift 2 ;;
        --include-tools)      INCLUDE_TOOLS="$2";    shift 2 ;;
        --exclude-tools)      EXCLUDE_TOOLS="$2";    shift 2 ;;
        -e|--env)             EXTRA_ENV+=("$2");     shift 2 ;;
        -b|--build)           DO_BUILD=1;            shift ;;
        -n|--no-defectdojo)   NO_DEFECTDOJO=1;       shift ;;
        --shell)              SHELL_MODE=1;           shift ;;
        -h|--help)            usage; exit 0 ;;
        --)                   shift; PASSTHROUGH=("$@"); break ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1 ;;
    esac
done

# ── Prereq check ──────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    error "docker not found. Please install Docker."
    exit 1
fi
if ! docker compose version &>/dev/null 2>&1; then
    error "docker compose plugin not found."
    exit 1
fi

# ── Load .env ─────────────────────────────────────────────────────────────────
if [[ -f .env ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
else
    warn ".env not found — copying from .env.example"
    cp .env.example .env
    set -a; source .env; set +a
fi

# ── Config file ───────────────────────────────────────────────────────────────
# The compose file already mounts ./config.toml:/app/config.toml:ro.
# If --config points elsewhere we add an extra -v to shadow that mount.
CONFIG_VOLUME_ARG=()
if [[ -n "$CONFIG_FILE" ]]; then
    CONFIG_FILE="$(realpath "$CONFIG_FILE")"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "Config file not found: $CONFIG_FILE"
        exit 1
    fi
    # Override the default config.toml mount with the specified file.
    CONFIG_VOLUME_ARG=(-v "${CONFIG_FILE}:/app/config.toml:ro")
    info "Using config: $CONFIG_FILE"
else
    if [[ ! -f config.toml ]]; then
        warn "config.toml not found — copying from config.example.toml"
        cp config.example.toml config.toml
    fi
    info "Using config: ./config.toml"
fi

# ── Ensure the Docker network exists ─────────────────────────────────────────
# vuln_scanner_network is declared external in docker-compose.scanner.yaml.
# Create it if it doesn't already exist (e.g. running without the full stack).
if ! docker network inspect vuln_scanner_network &>/dev/null; then
    info "Creating Docker network vuln_scanner_network..."
    docker network create vuln_scanner_network >/dev/null
fi

# ── Build scanner image ───────────────────────────────────────────────────────
if [[ "$DO_BUILD" -eq 1 ]]; then
    info "Building scanner image..."
    docker compose -f docker-compose.scanner.yaml build scanner
    success "Image built."
fi

# ── Assemble docker compose run arguments ─────────────────────────────────────
COMPOSE_RUN_ARGS=()

# Extra env vars from --env flags
for kv in "${EXTRA_ENV[@]}"; do
    COMPOSE_RUN_ARGS+=(-e "$kv")
done

# LLM env overrides
[[ -n "$LLM_MODEL"        ]] && COMPOSE_RUN_ARGS+=(-e "VS_LLM_MODEL=${LLM_MODEL}")
[[ -n "$LLM_MIN_SEVERITY" ]] && COMPOSE_RUN_ARGS+=(-e "VS_LLM_MIN_SEVERITY=${LLM_MIN_SEVERITY}")
[[ "$NO_DEFECTDOJO" -eq 1 ]] && COMPOSE_RUN_ARGS+=(-e "VS_DEFECTDOJO_URL=")

# Extra volume for custom config (empty when using default ./config.toml)
COMPOSE_RUN_ARGS+=("${CONFIG_VOLUME_ARG[@]+"${CONFIG_VOLUME_ARG[@]}"}")

# ── Assemble scanner CLI arguments ────────────────────────────────────────────
SCANNER_ARGS=()

[[ ${#TARGETS[@]} -gt 0 ]]  && SCANNER_ARGS+=(--targets "${TARGETS[@]}")
[[ -n "$MODE"              ]] && SCANNER_ARGS+=(--mode "$MODE")
[[ "$NO_LLM" -eq 1         ]] && SCANNER_ARGS+=(--no-llm)
[[ -n "$LLM_MODEL"         ]] && SCANNER_ARGS+=(--llm-model "$LLM_MODEL")
[[ -n "$LLM_MIN_SEVERITY"  ]] && SCANNER_ARGS+=(--llm-min-severity "$LLM_MIN_SEVERITY")
[[ -n "$INCLUDE_TOOLS"     ]] && SCANNER_ARGS+=(--include-tools "$INCLUDE_TOOLS")
[[ -n "$EXCLUDE_TOOLS"     ]] && SCANNER_ARGS+=(--exclude-tools "$EXCLUDE_TOOLS")

for fmt in "${FORMATS[@]}"; do
    SCANNER_ARGS+=(--formats "$fmt")
done

# Append manual passthrough args (everything after --)
SCANNER_ARGS+=("${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}")

# ── Run ───────────────────────────────────────────────────────────────────────
if [[ "$SHELL_MODE" -eq 1 ]]; then
    info "Opening shell inside scanner container..."
    info "Type 'exit' to leave. Reports mount at /app/reports, config at /app/config.toml."
    echo ""
    exec docker compose \
        -f docker-compose.scanner.yaml \
        run --rm -it \
        "${COMPOSE_RUN_ARGS[@]+"${COMPOSE_RUN_ARGS[@]}"}" \
        --entrypoint /bin/bash \
        scanner
fi

info "Starting scanner..."
echo ""

docker compose \
    -f docker-compose.scanner.yaml \
    run --rm \
    "${COMPOSE_RUN_ARGS[@]+"${COMPOSE_RUN_ARGS[@]}"}" \
    scanner \
    "${SCANNER_ARGS[@]+"${SCANNER_ARGS[@]}"}"

echo ""
success "Scan complete. Reports written to ./reports/"
