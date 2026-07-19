"""Port-based target routing.

After nmap / rustscan completes, parses open-port findings and derives
new scan targets:
  - HTTP service on any port  → http://host:port  (added to web scan)
  - HTTPS / SSL service       → https://host:port
  - Non-web services (SMB, SSH, …) are already handled by network tools
    using the original IP/HOST target — no new target needed.

The returned URLs are scope-validated and deduped before being appended
to the target list.
"""


import logging
from typing import TYPE_CHECKING

from vuln_scanner.tools.models import ScanResult

if TYPE_CHECKING:
    from vuln_scanner.scope import ScopeValidator

log = logging.getLogger(__name__)

# Services whose presence on a port implies an HTTP endpoint
_HTTP_SERVICES: frozenset[str] = frozenset({
    "http", "http-alt", "http-proxy",
    "www", "webcache", "websm",
    "8080", "8000", "8888", "3000", "8081", "9000",
})

_HTTPS_SERVICES: frozenset[str] = frozenset({
    "https", "https-alt", "ssl/http", "ssl/https", "ssl",
    "8443", "4443", "9443",
})

# Well-known HTTP ports (used when service name is ambiguous)
_HTTP_PORTS: frozenset[int] = frozenset({
    80, 8080, 8000, 8001, 8008, 8081, 8888, 3000, 5000,
    8082, 9000, 9080, 10080,
})
_HTTPS_PORTS: frozenset[int] = frozenset({
    443, 8443, 4443, 9443, 4433,
})


def _infer_scheme(port: int, service: str) -> str | None:
    """Return 'http' or 'https' if *port*/*service* looks like a web service."""
    svc = service.lower().strip()
    if svc in _HTTPS_SERVICES or port in _HTTPS_PORTS:
        return "https"
    if svc in _HTTP_SERVICES or port in _HTTP_PORTS:
        return "http"
    return None


def _make_url(host: str, port: int, scheme: str) -> str:
    # Omit standard ports from the URL
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def extract_web_targets(
    results: list[ScanResult],
    scope: "ScopeValidator | None" = None,
    existing: set[str] | None = None,
) -> list[str]:
    """Return new HTTP/HTTPS URLs derived from port scan findings.

    Only processes findings from tools named 'nmap' or 'rustscan'.
    ``existing`` is a set of targets already in the scan list — matching
    URLs are not returned again.
    """
    new_targets: list[str] = []
    seen: set[str] = set(existing or [])

    for result in results:
        if result.tool not in ("nmap", "rustscan"):
            continue
        for finding in result.findings:
            raw = finding.raw
            port_str = raw.get("port", "")
            service = raw.get("service", "")
            host = finding.target

            try:
                port = int(port_str)
            except (ValueError, TypeError):
                continue

            scheme = _infer_scheme(port, service)
            if scheme is None:
                continue

            url = _make_url(host, port, scheme)
            if url in seen:
                continue

            if scope and not scope.is_in_scope(url, discovered=True):
                log.debug("[port_router] OOS: %s", url)
                continue

            log.info("[port_router] Discovered web target: %s (port %d/%s)", url, port, service)
            seen.add(url)
            new_targets.append(url)

    return new_targets
