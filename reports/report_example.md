# Vulnerability Scan Report

**Generated:** 2026-07-13 23:45:47 UTC
**Hosts scanned:** 3
**Total findings:** 13

## Summary

| Host | Tool | Status | Findings | Duration |
|------|------|--------|----------|----------|
| `dvwa` | `amass` | ✅ success | 0 | 1.0s |
| `dvwa` | `gitleaks` | ✅ success | 0 | 0.0s |
| `dvwa` | `nikto` | ✅ success | 0 | 0.0s |
| `dvwa` | `nmap` | ✅ success | 1 | 6.5s |
| `dvwa` | `nuclei` | ✅ success | 0 | 0.1s |
| `dvwa` | `ssh-audit` | ✅ success | 0 | 0.1s |
| `dvwa` | `sslyze` | ✅ success | 0 | 0.2s |
| `dvwa` | `testssl` | ✅ success | 3 | 1.3s |
| `dvwa` | `trivy` | ✅ success | 0 | 12.6s |
| `dvwa` | `wapiti` | ✅ success | 0 | 0.3s |
| `dvwa` | `wpscan` | ✅ success | 0 | 0.5s |
| `dvwa` | `zap` | ✅ success | 0 | 0.4s |
| `juice-shop` | `amass` | ✅ success | 0 | 1.0s |
| `juice-shop` | `gitleaks` | ✅ success | 0 | 0.0s |
| `juice-shop` | `nikto` | ✅ success | 0 | 0.0s |
| `juice-shop` | `nmap` | ✅ success | 1 | 12.0s |
| `juice-shop` | `nuclei` | ✅ success | 0 | 0.1s |
| `juice-shop` | `ssh-audit` | ✅ success | 0 | 0.1s |
| `juice-shop` | `sslyze` | ✅ success | 0 | 0.2s |
| `juice-shop` | `testssl` | ✅ success | 3 | 1.3s |
| `juice-shop` | `trivy` | ✅ success | 0 | 8.6s |
| `juice-shop` | `wapiti` | ✅ success | 0 | 0.3s |
| `juice-shop` | `wpscan` | ✅ success | 0 | 0.5s |
| `juice-shop` | `zap` | ✅ success | 0 | 0.4s |
| `webgoat` | `amass` | ✅ success | 0 | 0.0s |
| `webgoat` | `gitleaks` | ✅ success | 0 | 0.0s |
| `webgoat` | `nikto` | ✅ success | 0 | 0.0s |
| `webgoat` | `nmap` | ✅ success | 2 | 6.5s |
| `webgoat` | `nuclei` | ✅ success | 0 | 0.1s |
| `webgoat` | `ssh-audit` | ✅ success | 0 | 0.1s |
| `webgoat` | `sslyze` | ✅ success | 0 | 0.2s |
| `webgoat` | `testssl` | ✅ success | 3 | 1.2s |
| `webgoat` | `trivy` | ✅ success | 0 | 8.3s |
| `webgoat` | `wapiti` | ✅ success | 0 | 0.3s |
| `webgoat` | `wpscan` | ✅ success | 0 | 0.5s |
| `webgoat` | `zap` | ✅ success | 0 | 0.3s |

## Findings

### dvwa

| Severity | Tool | Title | Description | CVEs |
|----------|------|-------|-------------|------|
| 🟡 MEDIUM | `testssl` | [engine_problem] No engine or GOST support via engine with your /usr/sbin/openssl | No engine or GOST support via engine with your /usr/sbin/openssl | — |
| 🟡 MEDIUM | `testssl` | [scanTime] Scan interrupted | Scan interrupted | — |
| ⚪ INFO | `nmap` | Open port 80/tcp — http (Apache httpd 2.4.67) | Port 80/tcp is open on 172.20.0.12. Service detected: http (Apache httpd 2.4.67). | — |
| ⚪ INFO | `testssl` | [scanProblem] Can't connect to '172.20.0.12:443' Make sure a firewall is not between you and your scanning target! | Can't connect to '172.20.0.12:443' Make sure a firewall is not between you and your scanning target! | — |

### juice-shop

| Severity | Tool | Title | Description | CVEs |
|----------|------|-------|-------------|------|
| 🟡 MEDIUM | `testssl` | [engine_problem] No engine or GOST support via engine with your /usr/sbin/openssl | No engine or GOST support via engine with your /usr/sbin/openssl | — |
| 🟡 MEDIUM | `testssl` | [scanTime] Scan interrupted | Scan interrupted | — |
| ⚪ INFO | `nmap` | Open port 3000/tcp — ppp | Port 3000/tcp is open on 172.20.0.11. Service detected: ppp. | — |
| ⚪ INFO | `testssl` | [scanProblem] Can't connect to '172.20.0.11:443' Make sure a firewall is not between you and your scanning target! | Can't connect to '172.20.0.11:443' Make sure a firewall is not between you and your scanning target! | — |

### webgoat

| Severity | Tool | Title | Description | CVEs |
|----------|------|-------|-------------|------|
| 🟡 MEDIUM | `testssl` | [engine_problem] No engine or GOST support via engine with your /usr/sbin/openssl | No engine or GOST support via engine with your /usr/sbin/openssl | — |
| 🟡 MEDIUM | `testssl` | [scanTime] Scan interrupted | Scan interrupted | — |
| ⚪ INFO | `nmap` | Open port 8080/tcp — http (Apache Tomcat ) | Port 8080/tcp is open on 172.20.0.9. Service detected: http (Apache Tomcat ). | — |
| ⚪ INFO | `nmap` | Open port 9090/tcp — http (Apache Tomcat ) | Port 9090/tcp is open on 172.20.0.9. Service detected: http (Apache Tomcat ). | — |
| ⚪ INFO | `testssl` | [scanProblem] Can't connect to '172.20.0.9:443' Make sure a firewall is not between you and your scanning target! | Can't connect to '172.20.0.9:443' Make sure a firewall is not between you and your scanning target! | — |
