"""Tests for classify_target() and tool.applies_to() — no real tool execution."""

from vuln_scanner.tools.enums import TargetType
from vuln_scanner.tools.target import classify_target


class TestClassifyTarget:
    def test_ipv4(self):
        assert TargetType.IP in classify_target("192.168.1.1")

    def test_ipv6(self):
        assert TargetType.IP in classify_target("::1")

    def test_cidr(self):
        assert TargetType.CIDR in classify_target("192.168.0.0/24")

    def test_http_url(self):
        types = classify_target("http://example.com")
        assert TargetType.URL in types
        assert TargetType.HOST not in types

    def test_https_url(self):
        assert TargetType.URL in classify_target("https://example.com/path?q=1")

    def test_hostname(self):
        types = classify_target("example.com")
        assert TargetType.HOST in types
        assert TargetType.IP not in types

    def test_absolute_path(self):
        types = classify_target("/home/user/project")
        assert TargetType.PATH in types

    def test_relative_path(self):
        types = classify_target("./project")
        assert TargetType.PATH in types

    def test_git_https(self):
        types = classify_target("https://github.com/user/repo")
        assert TargetType.REPO in types

    def test_git_dot_suffix(self):
        types = classify_target("https://github.com/user/repo.git")
        assert TargetType.REPO in types


class TestAppliesto:
    def test_network_tool_applies_to_ip(self):
        from vuln_scanner.tools.nmap import NmapTool
        assert NmapTool().applies_to("192.168.1.1")

    def test_network_tool_skips_url(self):
        from vuln_scanner.tools.nmap import NmapTool
        assert not NmapTool().applies_to("http://example.com")

    def test_network_tool_skips_path(self):
        from vuln_scanner.tools.nmap import NmapTool
        assert not NmapTool().applies_to("/home/user/code")

    def test_web_tool_applies_to_url(self):
        from vuln_scanner.tools.dalfox import DalfoxTool
        assert DalfoxTool().applies_to("http://target.com")

    def test_web_tool_skips_path(self):
        from vuln_scanner.tools.dalfox import DalfoxTool
        assert not DalfoxTool().applies_to("/home/user/code")

    def test_sast_tool_applies_to_path(self):
        from vuln_scanner.tools.bandit import BanditTool
        assert BanditTool().applies_to("/home/user/project")

    def test_sast_tool_skips_ip(self):
        from vuln_scanner.tools.bandit import BanditTool
        assert not BanditTool().applies_to("10.0.0.1")

    def test_sast_tool_skips_url(self):
        from vuln_scanner.tools.bandit import BanditTool
        assert not BanditTool().applies_to("http://example.com")

    def test_container_tool_applies_to_image(self):
        from vuln_scanner.tools.trivy import TrivyTool
        # container images resolve to HOST by our classifier (name:tag with no dots)
        # trivy accepts PATH or IMAGE
        tool = TrivyTool()
        assert tool.applies_to("/path/to/project")

    def test_applies_to_cidr(self):
        from vuln_scanner.tools.nmap import NmapTool
        assert NmapTool().applies_to("10.0.0.0/8")
