"""Tests for port-based web target routing."""

from vuln_scanner.tools.enums import Severity, ScanStatus
from vuln_scanner.tools.models import Finding, ScanResult
from vuln_scanner.port_router import extract_web_targets


def _result(tool: str, host: str, port: int, service: str) -> ScanResult:
    return ScanResult(
        tool=tool,
        target=host,
        status=ScanStatus.SUCCESS,
        findings=[
            Finding(
                title=f"Open port {port}/tcp — {service}",
                severity=Severity.INFO,
                description="",
                tool=tool,
                target=host,
                raw={"port": str(port), "protocol": "tcp", "service": service},
            )
        ],
    )


class TestPortRouter:
    def test_http_port_80_produces_plain_url(self):
        results = [_result("nmap", "10.0.0.1", 80, "http")]
        targets = extract_web_targets(results)
        assert "http://10.0.0.1" in targets

    def test_https_port_443_produces_https_url(self):
        results = [_result("nmap", "10.0.0.1", 443, "https")]
        targets = extract_web_targets(results)
        assert "https://10.0.0.1" in targets

    def test_non_standard_http_port_included_in_url(self):
        results = [_result("nmap", "10.0.0.1", 8443, "https")]
        targets = extract_web_targets(results)
        assert "https://10.0.0.1:8443" in targets

    def test_non_web_service_not_included(self):
        results = [_result("nmap", "10.0.0.1", 445, "microsoft-ds")]
        targets = extract_web_targets(results)
        assert targets == []

    def test_rustscan_findings_also_processed(self):
        results = [_result("rustscan", "10.0.0.2", 8080, "http-alt")]
        targets = extract_web_targets(results)
        assert any("10.0.0.2" in t for t in targets)

    def test_non_nmap_tool_ignored(self):
        results = [_result("nikto", "10.0.0.1", 80, "http")]
        assert extract_web_targets(results) == []

    def test_deduplication(self):
        results = [
            _result("nmap", "10.0.0.1", 80, "http"),
            _result("rustscan", "10.0.0.1", 80, "http"),
        ]
        targets = extract_web_targets(results)
        assert targets.count("http://10.0.0.1") == 1

    def test_existing_targets_excluded(self):
        results = [_result("nmap", "10.0.0.1", 80, "http")]
        targets = extract_web_targets(results, existing={"http://10.0.0.1"})
        assert targets == []

    def test_scope_filter_applied(self):
        from vuln_scanner.scope import ScopeValidator
        scope = ScopeValidator(include=["10.0.0.0/24"], exclude=[])
        results = [
            _result("nmap", "10.0.0.5", 80, "http"),
            _result("nmap", "192.168.1.1", 80, "http"),
        ]
        targets = extract_web_targets(results, scope=scope)
        assert any("10.0.0.5" in t for t in targets)
        assert not any("192.168.1.1" in t for t in targets)

    def test_well_known_ports_mapped(self):
        for port, scheme in [(3000, "http"), (5000, "http"), (8888, "http"), (4443, "https")]:
            results = [_result("nmap", "10.0.0.1", port, "unknown")]
            targets = extract_web_targets(results)
            assert any(str(port) in t or (port in (80, 443)) for t in targets), \
                f"Port {port} should produce a web target"
