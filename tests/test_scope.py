"""Tests for scope enforcement."""

from vuln_scanner.scope import ScopeValidator


class TestScopeValidator:
    def test_empty_include_passes_all_by_default(self):
        v = ScopeValidator(include=[], exclude=[])
        assert v.is_in_scope("https://anything.example.com")
        assert v.is_in_scope("192.168.1.1")

    def test_empty_include_strict_blocks_all(self):
        v = ScopeValidator(include=[], exclude=[], strict=True)
        assert not v.is_in_scope("https://example.com")

    def test_empty_include_blocks_discovered_assets(self):
        v = ScopeValidator(include=[], exclude=[])
        assert not v.is_in_scope("https://found.example.com", discovered=True)

    def test_glob_wildcard_match(self):
        v = ScopeValidator(include=["*.example.com"], exclude=[])
        assert v.is_in_scope("https://app.example.com")
        assert v.is_in_scope("sub.example.com")
        assert not v.is_in_scope("https://other.com")

    def test_cidr_match(self):
        v = ScopeValidator(include=["10.0.0.0/8"], exclude=[])
        assert v.is_in_scope("10.1.2.3")
        assert v.is_in_scope("http://10.50.0.1/path")
        assert not v.is_in_scope("192.168.1.1")

    def test_url_prefix_match(self):
        v = ScopeValidator(include=["https://app.example.com/api"], exclude=[])
        assert v.is_in_scope("https://app.example.com/api/v1/users")
        assert not v.is_in_scope("https://app.example.com/admin")

    def test_exact_hostname_match(self):
        v = ScopeValidator(include=["app.example.com"], exclude=[])
        assert v.is_in_scope("app.example.com")
        assert not v.is_in_scope("other.example.com")

    def test_exclude_wins_over_include(self):
        v = ScopeValidator(
            include=["*.example.com"],
            exclude=["admin.example.com"],
        )
        assert v.is_in_scope("app.example.com")
        assert not v.is_in_scope("admin.example.com")
        assert not v.is_in_scope("https://admin.example.com/login")

    def test_exclude_cidr(self):
        v = ScopeValidator(include=["10.0.0.0/8"], exclude=["10.0.0.1"])
        assert v.is_in_scope("10.0.0.2")
        assert not v.is_in_scope("10.0.0.1")

    def test_filter_returns_only_in_scope(self):
        v = ScopeValidator(include=["*.example.com"], exclude=["admin.example.com"])
        targets = ["app.example.com", "admin.example.com", "other.com"]
        result = v.filter(targets)
        assert result == ["app.example.com"]

    def test_filter_discovered_uses_include_list(self):
        v = ScopeValidator(include=["*.example.com"], exclude=[])
        assert v.filter(["sub.example.com", "evil.com"], discovered=True) == ["sub.example.com"]

    def test_case_insensitive_glob(self):
        v = ScopeValidator(include=["*.EXAMPLE.COM"], exclude=[])
        assert v.is_in_scope("sub.example.com")
