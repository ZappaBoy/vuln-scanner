#!/usr/bin/env bash
# poc.sh — End-to-end PoC: starts DefectDojo, vulnerable targets, and the scanner.
set -euo pipefail

# ---------------------------------------------------------------------------
# Colours & helpers
# ---------------------------------------------------------------------------
RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*" >&2; }
banner()  {
    cat <<EOF

${BOLD}${CYAN}══════════════════════════════════════════${NC}
  $*
${BOLD}${CYAN}══════════════════════════════════════════${NC}

EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
DD_PORT="${DEFECTDOJO_PORT:-8080}"
DD_URL="http://localhost:${DD_PORT}"
DD_ADMIN_USER="${DD_ADMIN_USER:-admin}"
DD_ADMIN_PASSWORD="${DD_ADMIN_PASSWORD:-admin}"
DD_PRODUCT="${DD_PRODUCT:-vuln-scanner-poc}"
DD_ENGAGEMENT="${DD_ENGAGEMENT:-PoC Automated Scan}"
SCAN_MODE="${SCAN_MODE:-active}"
MAX_WAIT_SECS="${MAX_WAIT_SECS:-300}"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
check_prerequisites() {
    banner "Checking prerequisites"
    local missing=0

    for cmd in docker curl python3; do
        if command -v "$cmd" &>/dev/null; then
            success "$cmd found"
        else
            error "$cmd not found"
            missing=$((missing + 1))
        fi
    done

    if docker compose version &>/dev/null 2>&1; then
        success "docker compose (plugin) found"
    else
        error "docker compose plugin not found"
        missing=$((missing + 1))
    fi

    if [ $missing -gt 0 ]; then
        error "Missing $missing prerequisite(s). Please install them and retry."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
load_env() {
    if [ ! -f .env ]; then
        warn ".env not found — copying from .env.example"
        cp .env.example .env
    fi

    # Export variables from .env (skip comments and empty lines)
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a

    # Re-read overridable vars now that .env is loaded
    DD_PORT="${DEFECTDOJO_PORT:-8080}"
    DD_URL="http://localhost:${DD_PORT}"
    DD_ADMIN_USER="${DD_ADMIN_USER:-admin}"
    DD_ADMIN_PASSWORD="${DD_ADMIN_PASSWORD:-admin}"

    success ".env loaded"
}

# ---------------------------------------------------------------------------
# Wait helpers
# ---------------------------------------------------------------------------
wait_for_http() {
    local url="$1"
    local label="$2"
    local max="${3:-$MAX_WAIT_SECS}"
    local elapsed=0
    local interval=5

    info "Waiting for ${label} at ${url} (max ${max}s)..."
    while ! curl -sf --max-time 5 "$url" &>/dev/null; do
        if [ "$elapsed" -ge "$max" ]; then
            error "Timed out waiting for ${label} after ${max}s"
            exit 1
        fi
        printf "."
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    echo ""
    success "${label} is up (${elapsed}s)"
}

wait_for_api() {
    # DefectDojo's API may lag behind nginx; wait until token auth endpoint responds.
    local url="${DD_URL}/api/v2/api-token-auth/"
    local max="${MAX_WAIT_SECS}"
    local elapsed=0
    local interval=5

    info "Waiting for DefectDojo API to be ready..."
    while true; do
        http_code=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 5 \
            -X POST "$url" \
            -H "Content-Type: application/json" \
            -d '{"username":"__probe__","password":"__probe__"}' 2>/dev/null || true)

        # 200 = auth ok, 400 = bad credentials (API is up), anything else = not ready
        if [ "$http_code" = "200" ] || [ "$http_code" = "400" ]; then
            break
        fi

        if [ "$elapsed" -ge "$max" ]; then
            error "Timed out waiting for DefectDojo API after ${max}s"
            exit 1
        fi
        printf "."
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    echo ""
    success "DefectDojo API is ready (${elapsed}s)"
}

# ---------------------------------------------------------------------------
# DefectDojo
# ---------------------------------------------------------------------------
start_defectdojo() {
    banner "Starting DefectDojo"
    docker compose up -d
    success "DefectDojo services started"
}

get_api_token() {
    info "Obtaining DefectDojo API token for user '${DD_ADMIN_USER}'..."

    local response
    response=$(curl -sf --max-time 10 \
        -X POST "${DD_URL}/api/v2/api-token-auth/" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"${DD_ADMIN_USER}\", \"password\": \"${DD_ADMIN_PASSWORD}\"}")

    DD_API_TOKEN=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

    if [ -z "$DD_API_TOKEN" ]; then
        error "Failed to obtain API token. Check admin credentials in .env."
        exit 1
    fi

    success "API token obtained"
}

# ---------------------------------------------------------------------------
# Vulnerable targets
# ---------------------------------------------------------------------------
start_targets() {
    banner "Starting vulnerable targets"
    docker compose -f docker-compose.target.yaml up -d
    success "Target containers started"
}

wait_for_targets() {
    info "Waiting for targets to become available..."
    wait_for_http "http://localhost:3000" "Juice Shop" 120
    wait_for_http "http://localhost:4280" "DVWA"       180
    wait_for_http "http://localhost:8888/WebGoat" "WebGoat" 120
}

# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
build_scanner() {
    banner "Building scanner image"
    docker compose -f docker-compose.yml -f docker-compose.scanner.yml build scanner
    success "Scanner image built"
}

run_scanner() {
    banner "Running scanner (mode: ${SCAN_MODE})"
    info "Targets: juice-shop, dvwa, webgoat"
    info "DefectDojo product: ${DD_PRODUCT}"

    docker compose \
        -f docker-compose.yml \
        -f docker-compose.scanner.yml \
        run --rm \
        -e VS_DEFECTDOJO_API_KEY="$DD_API_TOKEN" \
        -e VS_DEFECTDOJO_PRODUCT="$DD_PRODUCT" \
        -e VS_DEFECTDOJO_ENGAGEMENT="$DD_ENGAGEMENT" \
        scanner \
            --targets juice-shop dvwa webgoat \
            --mode "$SCAN_MODE" \
            --defectdojo-url http://nginx:8080

    success "Scan complete"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    banner "PoC complete"

    cat <<EOF
  ${BOLD}DefectDojo${NC}
    URL:      ${DD_URL}
    User:     ${DD_ADMIN_USER} / ${DD_ADMIN_PASSWORD}
    Product:  ${DD_PRODUCT}

  ${BOLD}Targets${NC}
    Juice Shop  →  http://localhost:3000
    DVWA        →  http://localhost:4280
    WebGoat     →  http://localhost:8888/WebGoat

  ${BOLD}Reports${NC}
    Local:  ${SCRIPT_DIR}/reports/
    Remote: ${DD_URL}/product/

  ${BOLD}Teardown${NC}
    docker compose down -v
    docker compose -f docker-compose.target.yaml down -v

EOF
}

# ---------------------------------------------------------------------------
# Cleanup on failure
# ---------------------------------------------------------------------------
cleanup_on_error() {
    error "PoC failed. Leaving containers running for inspection."
    cat <<EOF
  Logs: ${CYAN}docker compose logs --tail=50${NC}
  Stop: ${CYAN}docker compose down -v && docker compose -f docker-compose.target.yaml down -v${NC}
EOF
}
trap cleanup_on_error ERR

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
banner "vuln-scanner PoC"

check_prerequisites
load_env
start_defectdojo
wait_for_http "${DD_URL}" "DefectDojo nginx" "$MAX_WAIT_SECS"
wait_for_api
get_api_token
start_targets
wait_for_targets
build_scanner
run_scanner
print_summary
