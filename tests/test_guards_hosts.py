"""Host extraction / canonicalization guards (scope-validation substrate)."""

from vuln_scanner.agents.guards import canonical_host, extract_hosts


def test_extract_ipv4_and_domain():
    hosts = extract_hosts("https://app.t.lab/x", "10.0.0.5:8080")
    assert "app.t.lab" in hosts
    assert "10.0.0.5" in hosts


def test_extract_ipv6_bare_and_bracketed():
    assert "2001:db8::1" in extract_hosts("connect 2001:db8::1 now")
    assert "2001:db8::1" in extract_hosts("[2001:db8::1]:443")


def test_extract_normalizes_homoglyph_dot():
    # U+3002 IDEOGRAPHIC FULL STOP must fold to '.' so the domain is seen.
    assert "evil.com" in extract_hosts("evil。com")


def test_extract_ignores_single_label_tokens():
    # Single-label hosts are intentionally NOT extracted here (avoids littering
    # free-text argv with false matches); the fail-closed target path handles them.
    assert extract_hosts("localhost internal-admin -sV") == set()


def test_canonical_host_variants():
    assert canonical_host("https://user:pw@app.t.lab:8443/path?q=1") == "app.t.lab"
    assert canonical_host("[2001:db8::1]:443") == "2001:db8::1"
    assert canonical_host("localhost") == "localhost"
    assert canonical_host("/only/a/path") == ""
