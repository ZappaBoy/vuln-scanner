"""Tests for AuthConfig resolution logic."""

from vuln_scanner.tools.models import AuthConfig


class TestAuthConfigForTarget:
    def test_returns_self_when_no_targets_configured(self):
        cfg = AuthConfig(bearer_token="global-token")
        result = cfg.for_target("https://example.com")
        assert result is cfg

    def test_returns_override_on_exact_match(self):
        override = AuthConfig(bearer_token="target-token")
        cfg = AuthConfig(
            bearer_token="global-token",
            targets={"https://app.example.com": override},
        )
        result = cfg.for_target("https://app.example.com")
        assert result is override
        assert result.bearer_token == "target-token"

    def test_falls_back_to_global_on_no_match(self):
        override = AuthConfig(bearer_token="target-token")
        cfg = AuthConfig(
            bearer_token="global-token",
            targets={"https://other.example.com": override},
        )
        result = cfg.for_target("https://unrelated.example.com")
        assert result is cfg
        assert result.bearer_token == "global-token"

    def test_override_does_not_inherit_global_credentials(self):
        """Per-target entry replaces — does not merge with — global config."""
        override = AuthConfig(username="target-user", password="target-pass")
        cfg = AuthConfig(
            bearer_token="global-token",
            targets={"10.0.0.50": override},
        )
        result = cfg.for_target("10.0.0.50")
        assert result.username == "target-user"
        assert result.bearer_token == ""  # not inherited from global

    def test_multiple_targets_independent(self):
        cfg = AuthConfig(
            targets={
                "https://app.example.com": AuthConfig(bearer_token="token-a"),
                "https://admin.example.com": AuthConfig(bearer_token="token-b"),
            }
        )
        assert cfg.for_target("https://app.example.com").bearer_token == "token-a"
        assert cfg.for_target("https://admin.example.com").bearer_token == "token-b"


class TestAuthConfigProperties:
    def test_cookie_string_joins_with_semicolon(self):
        cfg = AuthConfig(cookies={"session": "abc", "csrf": "xyz"})
        parts = cfg.cookie_string.split("; ")
        assert "session=abc" in parts
        assert "csrf=xyz" in parts

    def test_effective_headers_includes_bearer(self):
        cfg = AuthConfig(bearer_token="my-jwt")
        headers = cfg.effective_headers
        assert headers["Authorization"] == "Bearer my-jwt"

    def test_effective_headers_does_not_override_existing_authorization(self):
        cfg = AuthConfig(
            bearer_token="my-jwt",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert cfg.effective_headers["Authorization"] == "Basic dXNlcjpwYXNz"

    def test_effective_headers_includes_cookie_header(self):
        cfg = AuthConfig(cookies={"session": "s123"})
        assert "Cookie" in cfg.effective_headers

    def test_is_configured_false_when_empty(self):
        assert not AuthConfig().is_configured

    def test_is_configured_true_when_bearer_set(self):
        assert AuthConfig(bearer_token="tok").is_configured

    def test_is_configured_true_when_username_set(self):
        assert AuthConfig(username="user").is_configured

    def test_is_configured_true_when_cookies_set(self):
        assert AuthConfig(cookies={"k": "v"}).is_configured
