---

# VULNERABILITY ASSESSMENT REPORT

---

| | |
|:---|:---|
| **Classification** | CONFIDENTIAL |
| **Report Date** | 2026-07-18 |
| **Assessment Type** | Automated Security Scan |
| **Targets Assessed** | 6 |
| **Total Findings** | 223 |
| **Report Version** | 1.0 |

> **CONFIDENTIAL** — This report contains sensitive security information.
> Distribution is restricted to authorized recipients only.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope and Methodology](#scope-and-methodology)
3. [Severity Rating Guide](#severity-rating-guide)
4. [Findings Overview](#findings-overview)
5. [Detailed Findings](#detailed-findings)
   - [Target: https://pentest-ground.com:4280](#target-httpspentest-groundcom4280)
   - [Target: https://pentest-ground.com:5013](#target-httpspentest-groundcom5013)
   - [Target: https://pentest-ground.com:81](#target-httpspentest-groundcom81)
   - [Target: https://pentest-ground.com:9000](#target-httpspentest-groundcom9000)
   - [Target: juice-shop](#target-juice-shop)
   - [Target: webgoat](#target-webgoat)

Appendix A — [Scan Errors](#appendix-a--scan-errors)
Appendix B — [PoC Assets](#appendix-b--poc-assets)

---

## 1. Executive Summary

Findings show widespread TLS/SSL misconfigurations across multiple endpoints, creating MITM risk and potential data exposure due to missing HSTS, certificate transparency gaps, weak cipher suites, and insecure renegotiation. CSP policy gaps and mirrored client-side vulnerabilities (reflected XSS) along with stack-trace disclosures expand the attack surface and enable content injection, session data leakage, and information exposure. Top priority actions are to harden TLS across all endpoints (enable HSTS, enforce certificate transparency, enable OCSP stapling, use strong ciphers, disable insecure renegotiation, secure cookies) and implement robust CSP policies (object-src, base-uri, frame-ancestors) while mitigating XSS vectors and production error disclosures.

---

## 2. Scope and Methodology

### 2.1 Assessment Scope

The following targets were included in this assessment:

| # | Target | Type |
|---|--------|------|
| 1 | `https://pentest-ground.com:4280` | URL |
| 2 | `https://pentest-ground.com:5013` | URL |
| 3 | `https://pentest-ground.com:81` | URL |
| 4 | `https://pentest-ground.com:9000` | URL |
| 5 | `juice-shop` | HOST |
| 6 | `webgoat` | HOST |

### 2.2 Tools Executed

| Tool | Findings | Status |
|------|:--------:|--------|
| `wapiti` | 147 | Success |
| `subfinder` | 42 | Success |
| `puredns` | 18 | Success |
| `alterx` | 6 | Success |
| `wafw00f` | 4 | Success |
| `nmap` | 3 | Success |
| `rustscan` | 3 | Success |

### 2.3 Scan Configuration

| Parameter | Value |
|-----------|-------|
| Scan duration | 4391 seconds |
| Tools run | 62 |
| Tools with errors | 5 |
| Tools skipped (binary not found) | 39 |

---

## 3. Severity Rating Guide

| Rating | CVSS Range | Description |
|--------|:----------:|-------------|
| **🔴 CRITICAL** | 9.0 – 10.0 | Immediate exploitation likely; maximum business impact. |
| **🟠 HIGH** | 7.0 – 8.9 | Significant risk; exploitation probable with minimal effort. |
| **🟡 MEDIUM** | 4.0 – 6.9 | Moderate risk; exploitation requires specific conditions. |
| **🔵 LOW** | 0.1 – 3.9 | Limited risk; exploitation is difficult or low-impact. |
| **⚪ INFO** | N/A | Informational; no direct exploitability demonstrated. |

---

## 4. Findings Overview

### 4.1 Risk Distribution

| Severity | Count | Distribution |
|----------|------:|:-------------|
| 🔴 CRITICAL | 0 | — |
| 🟠 HIGH | 8 | █ |
| 🟡 MEDIUM | 22 | ██ |
| 🔵 LOW | 117 | ██████████ |
| ⚪ INFO | 76 | ███████ |

### 4.2 Findings by Target

| Target | HIGH | MEDIUM | LOW | INFO | Total |
|--------|:------:|:------:|:------:|:------:|------:|
| `https://pentest-ground.com:4280` | — | 2 | 14 | 5 | **21** |
| `https://pentest-ground.com:5013` | — | 1 | 7 | 5 | **13** |
| `https://pentest-ground.com:81` | — | 2 | 6 | 5 | **13** |
| `https://pentest-ground.com:9000` | — | 1 | 4 | 5 | **10** |
| `juice-shop` | — | — | — | 11 | **11** |
| `webgoat` | — | — | — | 42 | **42** |

---

## 5. Detailed Findings

### Target: https://pentest-ground.com:4280

| ID | Severity | Finding | Tool(s) | Confidence |
|----|----------|---------|---------|:----------:|
| F-001 | MEDIUM | TLS/SSL misconfigurations | wapiti | Medium |
| F-002 | MEDIUM | Stack Trace Disclosure | wapiti | High |
| F-007 | LOW | Content Security Policy Configuration | wapiti | Unknown |
| F-008 | LOW | Command execution via page | wapiti | Unknown |
| F-009 | LOW | Clickjacking Protection | wapiti | Unknown |
| F-010 | LOW | HTTP Strict Transport Security (HSTS) | wapiti | Unknown |
| F-011 | LOW | MIME Type Confusion | wapiti | Unknown |
| F-012 | LOW | HttpOnly Flag cookie | wapiti | Unknown |
| F-013 | LOW | Information Disclosure - Full Path | wapiti | Unknown |
| F-014 | LOW | Open Redirect via redirect | wapiti | Unknown |
| F-015 | LOW | Secure Flag cookie | wapiti | Unknown |
| F-016 | LOW | SQL Injection via username | wapiti | Unknown |
| F-017 | LOW | SQL Injection via id | wapiti | Unknown |
| F-018 | LOW | SQL Injection via token | wapiti | Unknown |
| F-019 | LOW | SQL Injection via Submit | wapiti | Unknown |
| F-020 | LOW | Anomaly: Internal Server Error | wapiti | Unknown |
| F-038 | INFO | Permutation: flag provided but not defined: -d | alterx | Unknown |
| F-039 | INFO | Subdomain: Unable to execute massdns. Make sure it is present and that the | puredns | Unknown |
| F-040 | INFO | Subdomain: path to the binary is added to the PATH environment variable. | puredns | Unknown |
| F-041 | INFO | Subdomain: Alternatively, specify the path to massdns using --bin | puredns | Unknown |
| F-042 | INFO | No WAF detected | wafw00f | Unknown |

#### F-001 — TLS/SSL misconfigurations

| Field | Detail |
|:------|--------|
| **Identifier** | F-001 |
| **Severity** | 🟡 MEDIUM |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Medium |
| **CWE** | CWE-16 |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Certificate doesn't use Extended Validation
Path: /

**Business Impact**

Requires attacker to perform MITM or force traffic to HTTP; attacker must be able to intercept network communications or perform DNS spoofing; otherwise misconfig is informational.

**Analyst Note**

> TLS/SSL misconfig and missing security headers widen susceptibility to information disclosure and traffic manipulation.

**Short-term Mitigation**

1. Disable CBC ciphers and enable AEAD ciphers; enforce TLS 1.2+/1.3. 

```
# Nginx example
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers on;
```

2. Redirect HTTP to HTTPS to prevent MITM over cleartext and enable HSTS. 

```
# HTTP->HTTPS redirect (Nginx)
server {
  listen 80;
  server_name pentest-ground.com www.pentest-ground.com;
  return 301 https://$host$request_uri;
}
```

3. Add HSTS and perform a quick verification afterwards. 

```
# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

4. Validate changes with TLS tests (and re-scan). 

```
openssl s_client -connect pentest-ground.com:4280 -servername pentest-ground.com -tls1_2
```

**Permanent Remediation**

1. Obtain and install a valid certificate that matches the domain and policy (EV if required by business policy). Install the certificate and full chain on the server.

```
# Example (NGINX)
ssl_certificate /etc/ssl/certs/pentest-ground.pem;
ssl_certificate_key /etc/ssl/private/pentest-ground.key;
```

2. Harden TLS configuration and ensure modern suites are offered (TLS 1.2/1.3). 

```
# Nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers on;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
```

3. Enable security headers and ensure HTTPS-only policy remains enforced. 

```
# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

4. Validate deployment with external TLS tests (SSL Labs/openssl). 

```
openssl s_client -connect pentest-ground.com:4280 -tls1_2 -servername pentest-ground.com
```

**Proof-of-Concept**

PoC scripts: `poc-004` (see Appendix B)

---

#### F-002 — Stack Trace Disclosure

| Field | Detail |
|:------|--------|
| **Identifier** | F-002 |
| **Severity** | 🟡 MEDIUM |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | High |
| **CWE** | CWE-209 |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Response discloses a PHP stack trace or error message: Stack trace:
#0
Path: /vulnerabilities/sqli/

**Business Impact**

Attacker can trigger a server error by requesting a vulnerable URL to reveal a PHP stack trace and file paths; no authentication beyond HTTP(S) access is required.

**Analyst Note**

> PHP stack traces and full path disclosures indicate improper error handling and information leakage.

**Short-term Mitigation**

1. Disable display of errors in production and enable logging.
2. Enforce runtime non-disclosure of errors in code.
3. Ensure web server configuration does not leak error details.
4. Route all errors to generic user-friendly pages.

```ini
; php.ini (production)
display_errors = Off
log_errors = On
error_log = /var/log/php-errors.log
```

```php
// Production bootstrap
ini_set('display_errors', '0');
ini_set('log_errors', '1');
```

```apache
# Apache vhost
php_flag display_errors Off
```

```php
// Generic error response (do not reveal traces)
http_response_code(500);
echo 'Internal Server Error';
```

**Permanent Remediation**

1. Implement centralized, non-disclosive error handling so no stack traces or internal paths are output to users.
2. Patch PHP/frameworks to latest secure versions and apply all security updates.
3. Audit application code to remove any code paths that print traces, var_dumps, or exception traces; use sanitized logs instead.
4. Consider adding a WAF or reverse proxy that blocks verbose error disclosures and enforces generic error pages for 5xx responses.

```php
// Centralized non-disclosing error handling
ini_set('display_errors', '0');
set_error_handler(function($severity, $message, $file, $line){
  error_log("PHP[$severity] $message in $file:$line");
  http_response_code(500);
  echo 'Internal Server Error';
});
set_exception_handler(function($e){
  error_log((string)$e);
  http_response_code(500);
  echo 'Internal Server Error';
});
```

```bash
# Patch and restart
apt-get update && apt-get upgrade -y
systemctl restart php7.x-fpm
```

```php
// Example: avoid leaking traces
// Do not output $e->getTraceAsString() or $e->getMessage() to the client
```

**Proof-of-Concept**

PoC scripts: `poc-010` (see Appendix B)

---

#### F-007 — Content Security Policy Configuration

| Field | Detail |
|:------|--------|
| **Identifier** | F-007 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

CSP is not set for URL: https://pentest-ground.com:4280/
Path: /

---

#### F-008 — Command execution via page

| Field | Detail |
|:------|--------|
| **Identifier** | F-008 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

PHP evaluation via injection in the parameter page
Path: /vulnerabilities/fi/
Parameter: page

---

#### F-009 — Clickjacking Protection

| Field | Detail |
|:------|--------|
| **Identifier** | F-009 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

X-Frame-Options is not set
Path: /

---

#### F-010 — HTTP Strict Transport Security (HSTS)

| Field | Detail |
|:------|--------|
| **Identifier** | F-010 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Strict-Transport-Security is not set
Path: /

---

#### F-011 — MIME Type Confusion

| Field | Detail |
|:------|--------|
| **Identifier** | F-011 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

X-Content-Type-Options is not set
Path: /

---

#### F-012 — HttpOnly Flag cookie

| Field | Detail |
|:------|--------|
| **Identifier** | F-012 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

HttpOnly flag is not set on the cookie 'security' set at 'https://pentest-ground.com:4280/'
Path: /

---

#### F-013 — Information Disclosure - Full Path

| Field | Detail |
|:------|--------|
| **Identifier** | F-013 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Response contains potential system path: /var/www/html/vulnerabilities/fi/source/low.php
Path: /vulnerabilities/fi/

---

#### F-014 — Open Redirect via redirect

| Field | Detail |
|:------|--------|
| **Identifier** | F-014 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Open Redirect via injection in the parameter redirect
Path: /vulnerabilities/open_redirect/source/low.php
Parameter: redirect

---

#### F-015 — Secure Flag cookie

| Field | Detail |
|:------|--------|
| **Identifier** | F-015 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Secure flag is not set on the cookie: 'security' set at 'https://pentest-ground.com:4280/'
Path: /

---

#### F-016 — SQL Injection via username

| Field | Detail |
|:------|--------|
| **Identifier** | F-016 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

SQL Injection (DBMS: MariaDB) via injection in the parameter username
Path: /vulnerabilities/brute/
Parameter: username

---

#### F-017 — SQL Injection via id

| Field | Detail |
|:------|--------|
| **Identifier** | F-017 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

SQL Injection (DBMS: MariaDB) via injection in the parameter id
Path: /vulnerabilities/sqli_blind/
Parameter: id

---

#### F-018 — SQL Injection via token

| Field | Detail |
|:------|--------|
| **Identifier** | F-018 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

SQL Injection via injection in the parameter token
Path: /vulnerabilities/javascript/
Parameter: token

---

#### F-019 — SQL Injection via Submit

| Field | Detail |
|:------|--------|
| **Identifier** | F-019 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

SQL Injection via injection in the parameter Submit
Path: /vulnerabilities/exec/
Parameter: Submit

---

#### F-020 — Anomaly: Internal Server Error

| Field | Detail |
|:------|--------|
| **Identifier** | F-020 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

The server responded with a 500 HTTP error code while attempting to inject a payload in the parameter id

---

#### F-038 — Permutation: flag provided but not defined: -d

| Field | Detail |
|:------|--------|
| **Identifier** | F-038 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | alterx |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Subdomain permutation generated: flag provided but not defined: -d

---

#### F-039 — Subdomain: Unable to execute massdns. Make sure it is present and that the

| Field | Detail |
|:------|--------|
| **Identifier** | F-039 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Unable to execute massdns. Make sure it is present and that the

---

#### F-040 — Subdomain: path to the binary is added to the PATH environment variable.

| Field | Detail |
|:------|--------|
| **Identifier** | F-040 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: path to the binary is added to the PATH environment variable.

---

#### F-041 — Subdomain: Alternatively, specify the path to massdns using --bin

| Field | Detail |
|:------|--------|
| **Identifier** | F-041 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Alternatively, specify the path to massdns using --bin

---

#### F-042 — No WAF detected

| Field | Detail |
|:------|--------|
| **Identifier** | F-042 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:4280 |
| **Detected By** | wafw00f |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

No WAF was detected on https://pentest-ground.com:4280.

---

### Target: https://pentest-ground.com:5013

| ID | Severity | Finding | Tool(s) | Confidence |
|----|----------|---------|---------|:----------:|
| F-003 | MEDIUM | TLS/SSL misconfigurations | wapiti | High |
| F-021 | LOW | Content Security Policy Configuration | wapiti | Unknown |
| F-022 | LOW | Clickjacking Protection | wapiti | Unknown |
| F-023 | LOW | HTTP Strict Transport Security (HSTS) | wapiti | Unknown |
| F-024 | LOW | MIME Type Confusion | wapiti | Unknown |
| F-025 | LOW | HttpOnly Flag cookie | wapiti | Unknown |
| F-026 | LOW | Information Disclosure - Full Path | wapiti | Unknown |
| F-027 | LOW | Secure Flag cookie | wapiti | Unknown |
| F-043 | INFO | Permutation: flag provided but not defined: -d | alterx | Unknown |
| F-044 | INFO | Subdomain: Unable to execute massdns. Make sure it is present and that the | puredns | Unknown |
| F-045 | INFO | Subdomain: path to the binary is added to the PATH environment variable. | puredns | Unknown |
| F-046 | INFO | Subdomain: Alternatively, specify the path to massdns using --bin | puredns | Unknown |
| F-047 | INFO | No WAF detected | wafw00f | Unknown |

#### F-003 — TLS/SSL misconfigurations

| Field | Detail |
|:------|--------|
| **Identifier** | F-003 |
| **Severity** | 🟡 MEDIUM |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | wapiti |
| **Confidence** | High |
| **CWE** | CWE-200 |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Certificate doesn't use Extended Validation
Path: /

**Business Impact**

Remote attacker must intercept or impersonate TLS traffic (MITM) to exploit missing HttpOnly/Secure flags, CSP, X-Frame-Options, and HSTS; no direct code execution. Primary risk is information leakage and session hijacking.

**Analyst Note**

> Wapiti flags TLS misconfigs (no CSP, no HttpOnly/Secure cookies, no HSTS) plus a non-EV certificate and outdated OpenSSL CCS vulnerability reference; potential full path disclosure detected at /solutions: /usr/bin/env.

**Short-term Mitigation**

1. Enforce HttpOnly, Secure, and SameSite cookie attributes in the application. Use framework-specific settings to ensure cookies are not accessible via JavaScript and are transmitted only over HTTPS.
```js
# Node.js (Express)
app.use((req, res, next) => {
  res.cookie('session', req.sessionID, { httpOnly: true, secure: true, sameSite: 'Lax' });
  next();
});
```
```py
# Django
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'
```

2. Enable HTTP Strict Transport Security (HSTS) on the web server.
```nginx
# nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```
```apache
# Apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

3. Add Content-Security-Policy (CSP) and X-Frame-Options to mitigate content-based attacks and clickjacking.
```nginx
# nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https:; object-src 'none'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
```
```apache
# Apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' https:; object-src 'none'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'"
Header always set X-Frame-Options "SAMEORIGIN"
```

4. Harden TLS configuration (disable weak protocols/ciphers and enable modern TLS).
```nginx
# nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384';
ssl_prefer_server_ciphers on;
```
```apache
# Apache
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
SSLHonorCipherOrder on
```

**Permanent Remediation**

1. Obtain and install a valid CA-signed certificate (and serve the complete chain). If using Let’s Encrypt: 
```bash
certbot certonly --nginx -d pentest-ground.com -d www.pentest-ground.com
```
Then ensure the server points to the new chain:
```nginx
ssl_certificate /etc/letsencrypt/live/pentest-ground.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/pentest-ground.com/privkey.pem;
```

2. Enforce modern TLS on the server (TLS 1.2/1.3) and disable legacy protocols/ciphers.
```nginx
# nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384';
ssl_prefer_server_ciphers on;
```

3. Implement security headers and ensure cookie attributes in code and server config.
```nginx
# nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https:; object-src 'none'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
```
```py
# Django (cookie hygiene reminder in code)
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'
```

4. Verify and monitor post-remediation.
```bash
# TLS/headers verification
openssl s_client -connect pentest-ground.com:5013 -servername pentest-ground.com
curl -I https://pentest-ground.com:5013
# Optional: SSL Labs test (external): https://www.ssllabs.com/ssltest/
```


**Proof-of-Concept**

PoC scripts: `poc-011` (see Appendix B)

---

#### F-021 — Content Security Policy Configuration

| Field | Detail |
|:------|--------|
| **Identifier** | F-021 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

CSP is not set for URL: https://pentest-ground.com:5013/
Path: /

---

#### F-022 — Clickjacking Protection

| Field | Detail |
|:------|--------|
| **Identifier** | F-022 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

X-Frame-Options is not set
Path: /

---

#### F-023 — HTTP Strict Transport Security (HSTS)

| Field | Detail |
|:------|--------|
| **Identifier** | F-023 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Strict-Transport-Security is not set
Path: /

---

#### F-024 — MIME Type Confusion

| Field | Detail |
|:------|--------|
| **Identifier** | F-024 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

X-Content-Type-Options is not set
Path: /

---

#### F-025 — HttpOnly Flag cookie

| Field | Detail |
|:------|--------|
| **Identifier** | F-025 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

HttpOnly flag is not set on the cookie 'env' set at 'https://pentest-ground.com:5013/'
Path: /

---

#### F-026 — Information Disclosure - Full Path

| Field | Detail |
|:------|--------|
| **Identifier** | F-026 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Response contains potential system path: /usr/bin/env
Path: /solutions

---

#### F-027 — Secure Flag cookie

| Field | Detail |
|:------|--------|
| **Identifier** | F-027 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Secure flag is not set on the cookie: 'env' set at 'https://pentest-ground.com:5013/'
Path: /

---

#### F-043 — Permutation: flag provided but not defined: -d

| Field | Detail |
|:------|--------|
| **Identifier** | F-043 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | alterx |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Subdomain permutation generated: flag provided but not defined: -d

---

#### F-044 — Subdomain: Unable to execute massdns. Make sure it is present and that the

| Field | Detail |
|:------|--------|
| **Identifier** | F-044 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Unable to execute massdns. Make sure it is present and that the

---

#### F-045 — Subdomain: path to the binary is added to the PATH environment variable.

| Field | Detail |
|:------|--------|
| **Identifier** | F-045 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: path to the binary is added to the PATH environment variable.

---

#### F-046 — Subdomain: Alternatively, specify the path to massdns using --bin

| Field | Detail |
|:------|--------|
| **Identifier** | F-046 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Alternatively, specify the path to massdns using --bin

---

#### F-047 — No WAF detected

| Field | Detail |
|:------|--------|
| **Identifier** | F-047 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:5013 |
| **Detected By** | wafw00f |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

No WAF was detected on https://pentest-ground.com:5013.

---

### Target: https://pentest-ground.com:81

| ID | Severity | Finding | Tool(s) | Confidence |
|----|----------|---------|---------|:----------:|
| F-004 | MEDIUM | Reflected Cross Site Scripting via title | wapiti | High |
| F-005 | MEDIUM | TLS/SSL misconfigurations | wapiti | Medium |
| F-028 | LOW | Content Security Policy Configuration | wapiti | Unknown |
| F-029 | LOW | Clickjacking Protection | wapiti | Unknown |
| F-030 | LOW | HTTP Strict Transport Security (HSTS) | wapiti | Unknown |
| F-031 | LOW | MIME Type Confusion | wapiti | Unknown |
| F-032 | LOW | HttpOnly Flag cookie | wapiti | Unknown |
| F-033 | LOW | Secure Flag cookie | wapiti | Unknown |
| F-048 | INFO | Permutation: flag provided but not defined: -d | alterx | Unknown |
| F-049 | INFO | Subdomain: Unable to execute massdns. Make sure it is present and that the | puredns | Unknown |
| F-050 | INFO | Subdomain: path to the binary is added to the PATH environment variable. | puredns | Unknown |
| F-051 | INFO | Subdomain: Alternatively, specify the path to massdns using --bin | puredns | Unknown |
| F-052 | INFO | No WAF detected | wafw00f | Unknown |

#### F-004 — Reflected Cross Site Scripting via title

| Field | Detail |
|:------|--------|
| **Identifier** | F-004 |
| **Severity** | 🟡 MEDIUM |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | wapiti |
| **Confidence** | High |
| **CWE** | CWE-79 |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Reflected Cross Site Scripting vulnerability found via injection in the parameter title
Path: /2/edit
Parameter: title

**Business Impact**

Attacker crafts a URL to /2/edit?title=<payload> and lures a victim to click it; the payload executes in the victim's browser in the site's origin, enabling script execution and potential data leakage; no special prerequisites beyond user interaction.

**Analyst Note**

> Lack of CSP, X-Frame-Options, and X-Content-Type-Options; HttpOnly not set on SessionID cookie; cookies not marked Secure; HSTS not set; overall weak client-side protections increase risk of XSS and session hijacking.

**Short-term Mitigation**

1. Ensure server-side escaping for all user input used in HTML rendering.\n2. Validate/sanitize the title at the input boundary with a whitelist (for example allow only letters, numbers, spaces, and .,_-).\n3. Enable a Content-Security-Policy (CSP) header to restrict script execution and disallow inline scripts.\n4. Deploy a Web Application Firewall (WAF) rule to block reflected XSS in the title query parameter and enable logging/alerting.

**Permanent Remediation**

1. Implement robust, consistent output encoding: treat title as data, escape before rendering in all templates; prefer framework auto-escaping.\n2. Centralize input validation with a strict allowlist (regex: ^[A-Za-z0-9 .,_-]+$) and reject any non-conforming values at the API boundary.\n3. Ensure application templates do not render raw user input; upgrade/patch templating engine to latest, enable auto-escaping by default.\n4. Add/verify security controls (CSP, WAF) and re-test with automated scanners to confirm removal of XSS vector.

---

#### F-005 — TLS/SSL misconfigurations

| Field | Detail |
|:------|--------|
| **Identifier** | F-005 |
| **Severity** | 🟡 MEDIUM |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | wapiti |
| **Confidence** | Medium |
| **CWE** | CWE-310 |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Certificate doesn't use Extended Validation
Path: /

**Business Impact**

Remote, no authentication required; attacker on the network can attempt MITM to capture/modify traffic due to TLS misconfig, and lack of HttpOnly/Secure cookies enables session theft via XSS; OpenSSL CCS vulnerability and lack of secure renegotiation add risk.

**Analyst Note**

> TLS/SSL misconfig includes non-EV cert with short expiry and missing security headers/cookie flags; potential exposure includes session tokens and lack of defense-in-depth.

**Short-term Mitigation**

1. Update TLS stack to latest OpenSSL/SSL libraries and patch vendor packages to fix CCS vulnerability and secure renegotiation.
```bash
# Example (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install --only-upgrade openssl	sudo systemctl restart nginx
```
2. Enforce modern TLS configuration and cipher suites; disable TLS 1.0/1.1, enable TLS 1.2/1.3, and use forward-secret ciphers.
```nginx
# nginx example
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_256_GCM_SHA384';
ssl_prefer_server_ciphers on;
ssl_session_tickets off;
```
3. Harden cookies and headers: set HttpOnly and Secure on all cookies, enable SameSite, and enable HSTS.
```nginx
# nginx example
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```
```js
// If app sets cookies, ensure flags are set
response.cookie('session', value, { httpOnly: true, secure: true, sameSite: 'Strict' });
```
4. Prefer standard HTTPS port and ensure a proper certificate chain; if currently on 81, redirect or move to 443.
```nginx
server {
  listen 81;
  server_name pentest-ground.com;
  return 301 https://$host$request_uri;
}
```

**Permanent Remediation**

1. Deploy a production-grade TLS configuration with current libraries: disable old protocols, enable TLS 1.2/1.3, use strong ECDHE ciphers, and turn off session tickets.
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_256_GCM_SHA384';
ssl_prefer_server_ciphers on;
ssl_session_tickets off;
```
2. Obtain and install a trusted certificate (prefer DV/EV per policy) and bind to port 443 on a valid hostname; ensure full certificate chain is served.
```bash
# Example with Certbot (NGINX)
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d pentest-ground.com -d www.pentest-ground.com
```
Verify chain and validity:
```bash
openssl x509 -in /etc/letsencrypt/live/pentest-ground.com/fullchain.pem -noout -dates
openssl s_client -connect pentest-ground.com:443 -servername pentest-ground.com
```
3. Secure cookies across the app: enforce HttpOnly, Secure, and SameSite, and enable cookie-based CSRF protections as appropriate.
```js
// Node.js Express example
app.use(require('cookie-session')({ name: 'session', keys: ['KEY'], httpOnly: true, secure: true, sameSite: 'Strict' }));
```
4. Validate after change: run post-deployment TLS/SSL checks and monitor for TLS renegotiation issues.
```bash
git clone https://github.com/drwetter/testssl.sh.git
./testssl.sh pentest-ground.com:443
```

---

#### F-028 — Content Security Policy Configuration

| Field | Detail |
|:------|--------|
| **Identifier** | F-028 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

CSP is not set for URL: https://pentest-ground.com:81/
Path: /

---

#### F-029 — Clickjacking Protection

| Field | Detail |
|:------|--------|
| **Identifier** | F-029 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

X-Frame-Options is not set
Path: /

---

#### F-030 — HTTP Strict Transport Security (HSTS)

| Field | Detail |
|:------|--------|
| **Identifier** | F-030 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Strict-Transport-Security is not set
Path: /

---

#### F-031 — MIME Type Confusion

| Field | Detail |
|:------|--------|
| **Identifier** | F-031 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

X-Content-Type-Options is not set
Path: /

---

#### F-032 — HttpOnly Flag cookie

| Field | Detail |
|:------|--------|
| **Identifier** | F-032 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

HttpOnly flag is not set on the cookie 'SessionID' set at 'https://pentest-ground.com:81/'
Path: /

---

#### F-033 — Secure Flag cookie

| Field | Detail |
|:------|--------|
| **Identifier** | F-033 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Secure flag is not set on the cookie: 'SessionID' set at 'https://pentest-ground.com:81/'
Path: /

---

#### F-048 — Permutation: flag provided but not defined: -d

| Field | Detail |
|:------|--------|
| **Identifier** | F-048 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | alterx |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Subdomain permutation generated: flag provided but not defined: -d

---

#### F-049 — Subdomain: Unable to execute massdns. Make sure it is present and that the

| Field | Detail |
|:------|--------|
| **Identifier** | F-049 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Unable to execute massdns. Make sure it is present and that the

---

#### F-050 — Subdomain: path to the binary is added to the PATH environment variable.

| Field | Detail |
|:------|--------|
| **Identifier** | F-050 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: path to the binary is added to the PATH environment variable.

---

#### F-051 — Subdomain: Alternatively, specify the path to massdns using --bin

| Field | Detail |
|:------|--------|
| **Identifier** | F-051 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Alternatively, specify the path to massdns using --bin

---

#### F-052 — No WAF detected

| Field | Detail |
|:------|--------|
| **Identifier** | F-052 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:81 |
| **Detected By** | wafw00f |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

No WAF was detected on https://pentest-ground.com:81.

---

### Target: https://pentest-ground.com:9000

| ID | Severity | Finding | Tool(s) | Confidence |
|----|----------|---------|---------|:----------:|
| F-006 | MEDIUM | TLS/SSL misconfigurations | wapiti | Medium |
| F-034 | LOW | Content Security Policy Configuration | wapiti | Unknown |
| F-035 | LOW | Clickjacking Protection | wapiti | Unknown |
| F-036 | LOW | HTTP Strict Transport Security (HSTS) | wapiti | Unknown |
| F-037 | LOW | MIME Type Confusion | wapiti | Unknown |
| F-053 | INFO | Permutation: flag provided but not defined: -d | alterx | Unknown |
| F-054 | INFO | Subdomain: Unable to execute massdns. Make sure it is present and that the | puredns | Unknown |
| F-055 | INFO | Subdomain: path to the binary is added to the PATH environment variable. | puredns | Unknown |
| F-056 | INFO | Subdomain: Alternatively, specify the path to massdns using --bin | puredns | Unknown |
| F-057 | INFO | No WAF detected | wafw00f | Unknown |

#### F-006 — TLS/SSL misconfigurations

| Field | Detail |
|:------|--------|
| **Identifier** | F-006 |
| **Severity** | 🟡 MEDIUM |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:9000 |
| **Detected By** | wapiti |
| **Confidence** | Medium |
| **CWE** | CWE-327 |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Certificate doesn't use Extended Validation
Path: /

**Business Impact**

Remote attacker in MITM position can trigger the CCS flaw in affected OpenSSL during TLS handshake; no user interaction or credentials required.

**Analyst Note**

> EV not used; OCSP stapling, Certificate Transparency, and HSTS not set; CCS vulnerability present and secure renegotiation not supported.

**Short-term Mitigation**

1. Enable HSTS on HTTPS endpoints to enforce TLS usage and reduce MITM risks.
   ```nginx
   add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;
   ```
2. Redirect all HTTP traffic to HTTPS to ensure encrypted sessions.
   ```nginx
   server {
     listen 80;
     server_name pentest-ground.com www.pentest-ground.com;
     return 301 https://$host$request_uri;
   }
   ```
3. Enforce strong TLS by disabling legacy protocols/ciphers and requiring TLS 1.2/1.3.
   ```nginx
   ssl_protocols TLSv1.2 TLSv1.3;
   ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
   ssl_prefer_server_ciphers on;
   ```
4. Patch OpenSSL and web server to latest versions and verify patches are applied.
   ```bash
   sudo apt-get update
   sudo apt-get install --only-upgrade openssl nginx
   openssl version
   nginx -v
   ```

**Permanent Remediation**

1. Obtain and install a valid TLS certificate from a trusted CA (DV/OV/EV as required) and configure it on the server.
   ```nginx
   ssl_certificate /etc/ssl/certs/pentest-ground_com.crt;
   ssl_certificate_key /etc/ssl/private/pentest-ground_com.key;
   ```
2. Enable HSTS with includeSubDomains and preload to enforce TLS across all subdomains.
   ```nginx
   add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;
   ```
3. Harden TLS configuration and maintain patching cadence (disable legacy protocols, keep ciphers strong, patch promptly).
   ```bash
   sudo apt-get update
   sudo apt-get install --only-upgrade openssl nginx
   # Verify TLS configuration as part of hardening
   openssl s_client -connect pentest-ground.com:9000 -tls1_2
   ```
4. Validate and monitor post-remediation using external tests.
   ```bash
   ./testssl.sh pentest-ground.com:9000
   ```

**Proof-of-Concept**

PoC scripts: `poc-017` (see Appendix B)

---

#### F-034 — Content Security Policy Configuration

| Field | Detail |
|:------|--------|
| **Identifier** | F-034 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:9000 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

CSP is not set for URL: https://pentest-ground.com:9000/
Path: /

---

#### F-035 — Clickjacking Protection

| Field | Detail |
|:------|--------|
| **Identifier** | F-035 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:9000 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

X-Frame-Options is not set
Path: /

---

#### F-036 — HTTP Strict Transport Security (HSTS)

| Field | Detail |
|:------|--------|
| **Identifier** | F-036 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:9000 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Strict-Transport-Security is not set
Path: /

---

#### F-037 — MIME Type Confusion

| Field | Detail |
|:------|--------|
| **Identifier** | F-037 |
| **Severity** | 🔵 LOW |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:9000 |
| **Detected By** | wapiti |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

X-Content-Type-Options is not set
Path: /

---

#### F-053 — Permutation: flag provided but not defined: -d

| Field | Detail |
|:------|--------|
| **Identifier** | F-053 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:9000 |
| **Detected By** | alterx |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Subdomain permutation generated: flag provided but not defined: -d

---

#### F-054 — Subdomain: Unable to execute massdns. Make sure it is present and that the

| Field | Detail |
|:------|--------|
| **Identifier** | F-054 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:9000 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Unable to execute massdns. Make sure it is present and that the

---

#### F-055 — Subdomain: path to the binary is added to the PATH environment variable.

| Field | Detail |
|:------|--------|
| **Identifier** | F-055 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:9000 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: path to the binary is added to the PATH environment variable.

---

#### F-056 — Subdomain: Alternatively, specify the path to massdns using --bin

| Field | Detail |
|:------|--------|
| **Identifier** | F-056 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:9000 |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Alternatively, specify the path to massdns using --bin

---

#### F-057 — No WAF detected

| Field | Detail |
|:------|--------|
| **Identifier** | F-057 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | https://pentest-ground.com:9000 |
| **Detected By** | wafw00f |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

No WAF was detected on https://pentest-ground.com:9000.

---

### Target: juice-shop

| ID | Severity | Finding | Tool(s) | Confidence |
|----|----------|---------|---------|:----------:|
| F-058 | INFO | Permutation: flag provided but not defined: -d | alterx | Unknown |
| F-059 | INFO | Open port 3000/tcp — ppp | nmap, rustscan | Unknown |
| F-060 | INFO | Subdomain: Unable to execute massdns. Make sure it is present and that the | puredns | Unknown |
| F-061 | INFO | Subdomain: path to the binary is added to the PATH environment variable. | puredns | Unknown |
| F-062 | INFO | Subdomain: Alternatively, specify the path to massdns using --bin | puredns | Unknown |
| F-063 | INFO | Subdomain: hostmaster.hostmaster.juice-shop | subfinder | Unknown |
| F-064 | INFO | Subdomain: hostmaster.juice-shop | subfinder | Unknown |
| F-065 | INFO | Subdomain: www.juice-shop | subfinder | Unknown |
| F-066 | INFO | Subdomain: mx1.juice-shop | subfinder | Unknown |
| F-067 | INFO | Subdomain: mail.juice-shop | subfinder | Unknown |
| F-068 | INFO | Subdomain: hostmaster.hostmaster.hostmaster.juice-shop | subfinder | Unknown |

#### F-058 — Permutation: flag provided but not defined: -d

| Field | Detail |
|:------|--------|
| **Identifier** | F-058 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | alterx |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Subdomain permutation generated: flag provided but not defined: -d

---

#### F-059 — Open port 3000/tcp — ppp

| Field | Detail |
|:------|--------|
| **Identifier** | F-059 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | 172.20.0.6 |
| **Detected By** | nmap, rustscan |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Port 3000/tcp is open on 172.20.0.6. Service detected: ppp.

---

#### F-060 — Subdomain: Unable to execute massdns. Make sure it is present and that the

| Field | Detail |
|:------|--------|
| **Identifier** | F-060 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Unable to execute massdns. Make sure it is present and that the

---

#### F-061 — Subdomain: path to the binary is added to the PATH environment variable.

| Field | Detail |
|:------|--------|
| **Identifier** | F-061 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: path to the binary is added to the PATH environment variable.

---

#### F-062 — Subdomain: Alternatively, specify the path to massdns using --bin

| Field | Detail |
|:------|--------|
| **Identifier** | F-062 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Alternatively, specify the path to massdns using --bin

---

#### F-063 — Subdomain: hostmaster.hostmaster.juice-shop

| Field | Detail |
|:------|--------|
| **Identifier** | F-063 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: hostmaster.hostmaster.juice-shop via rapiddns

---

#### F-064 — Subdomain: hostmaster.juice-shop

| Field | Detail |
|:------|--------|
| **Identifier** | F-064 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: hostmaster.juice-shop via rapiddns

---

#### F-065 — Subdomain: www.juice-shop

| Field | Detail |
|:------|--------|
| **Identifier** | F-065 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: www.juice-shop via rapiddns

---

#### F-066 — Subdomain: mx1.juice-shop

| Field | Detail |
|:------|--------|
| **Identifier** | F-066 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: mx1.juice-shop via rapiddns

---

#### F-067 — Subdomain: mail.juice-shop

| Field | Detail |
|:------|--------|
| **Identifier** | F-067 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: mail.juice-shop via rapiddns

---

#### F-068 — Subdomain: hostmaster.hostmaster.hostmaster.juice-shop

| Field | Detail |
|:------|--------|
| **Identifier** | F-068 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: hostmaster.hostmaster.hostmaster.juice-shop via rapiddns

---

### Target: webgoat

| ID | Severity | Finding | Tool(s) | Confidence |
|----|----------|---------|---------|:----------:|
| F-069 | INFO | Permutation: flag provided but not defined: -d | alterx | Unknown |
| F-070 | INFO | Open port 8080/tcp — http (Apache Tomcat ) | nmap, rustscan | Unknown |
| F-071 | INFO | Open port 9090/tcp — http (Apache Tomcat ) | nmap, rustscan | Unknown |
| F-072 | INFO | Subdomain: Unable to execute massdns. Make sure it is present and that the | puredns | Unknown |
| F-073 | INFO | Subdomain: path to the binary is added to the PATH environment variable. | puredns | Unknown |
| F-074 | INFO | Subdomain: Alternatively, specify the path to massdns using --bin | puredns | Unknown |
| F-075 | INFO | Subdomain: webmail.leonardtestnew.webgoat | subfinder | Unknown |
| F-076 | INFO | Subdomain: www.webgoat | subfinder | Unknown |
| F-077 | INFO | Subdomain: webmail.scottdemo.webgoat | subfinder | Unknown |
| F-078 | INFO | Subdomain: cpanel.leonardtestnew.webgoat | subfinder | Unknown |
| F-079 | INFO | Subdomain: www.leonardtestnew.webgoat | subfinder | Unknown |
| F-080 | INFO | Subdomain: cpanel.leonardtestfriday.webgoat | subfinder | Unknown |
| F-081 | INFO | Subdomain: webdisk.acag.webgoat | subfinder | Unknown |
| F-082 | INFO | Subdomain: acag.webgoat | subfinder | Unknown |
| F-083 | INFO | Subdomain: mail.leonardtestnew.webgoat | subfinder | Unknown |
| F-084 | INFO | Subdomain: webdisk.leonardtestnew.webgoat | subfinder | Unknown |
| F-085 | INFO | Subdomain: www.acag.webgoat | subfinder | Unknown |
| F-086 | INFO | Subdomain: www.leonardtestfriday.webgoat | subfinder | Unknown |
| F-087 | INFO | Subdomain: cpanel.acag.webgoat | subfinder | Unknown |
| F-088 | INFO | Subdomain: mx.webgoat | subfinder | Unknown |
| F-089 | INFO | Subdomain: leonardtestnew.webgoat | subfinder | Unknown |
| F-090 | INFO | Subdomain: webdisk.leonardtestfriday.webgoat | subfinder | Unknown |
| F-091 | INFO | Subdomain: www.beta.webgoat | subfinder | Unknown |
| F-092 | INFO | Subdomain: donna.webgoat | subfinder | Unknown |
| F-093 | INFO | Subdomain: 220-khan.webgoat | subfinder | Unknown |
| F-094 | INFO | Subdomain: www.donna.webgoat | subfinder | Unknown |
| F-095 | INFO | Subdomain: mail.leonardtestfriday.webgoat | subfinder | Unknown |
| F-096 | INFO | Subdomain: www.scottdemo.webgoat | subfinder | Unknown |
| F-097 | INFO | Subdomain: webdisk.scottdemo.webgoat | subfinder | Unknown |
| F-098 | INFO | Subdomain: ns1.webgoat | subfinder | Unknown |
| F-099 | INFO | Subdomain: srv1.webgoat | subfinder | Unknown |
| F-100 | INFO | Subdomain: webmail.acag.webgoat | subfinder | Unknown |
| F-101 | INFO | Subdomain: ns2.webgoat | subfinder | Unknown |
| F-102 | INFO | Subdomain: cpanel.scottdemo.webgoat | subfinder | Unknown |
| F-103 | INFO | Subdomain: admin.webgoat | subfinder | Unknown |
| F-104 | INFO | Subdomain: beta.webgoat | subfinder | Unknown |
| F-105 | INFO | Subdomain: scottdemo.webgoat | subfinder | Unknown |
| F-106 | INFO | Subdomain: webmail.leonardtestfriday.webgoat | subfinder | Unknown |
| F-107 | INFO | Subdomain: khan.webgoat | subfinder | Unknown |
| F-108 | INFO | Subdomain: leonardtestfriday.webgoat | subfinder | Unknown |
| F-109 | INFO | Subdomain: mail.scottdemo.webgoat | subfinder | Unknown |
| F-110 | INFO | Subdomain: mail.acag.webgoat | subfinder | Unknown |

#### F-069 — Permutation: flag provided but not defined: -d

| Field | Detail |
|:------|--------|
| **Identifier** | F-069 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | alterx |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Subdomain permutation generated: flag provided but not defined: -d

---

#### F-070 — Open port 8080/tcp — http (Apache Tomcat )

| Field | Detail |
|:------|--------|
| **Identifier** | F-070 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | 172.20.0.3 |
| **Detected By** | nmap, rustscan |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Port 8080/tcp is open on 172.20.0.3. Service detected: http (Apache Tomcat ).

---

#### F-071 — Open port 9090/tcp — http (Apache Tomcat )

| Field | Detail |
|:------|--------|
| **Identifier** | F-071 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | 172.20.0.3 |
| **Detected By** | nmap, rustscan |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Port 9090/tcp is open on 172.20.0.3. Service detected: http (Apache Tomcat ).

---

#### F-072 — Subdomain: Unable to execute massdns. Make sure it is present and that the

| Field | Detail |
|:------|--------|
| **Identifier** | F-072 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Unable to execute massdns. Make sure it is present and that the

---

#### F-073 — Subdomain: path to the binary is added to the PATH environment variable.

| Field | Detail |
|:------|--------|
| **Identifier** | F-073 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: path to the binary is added to the PATH environment variable.

---

#### F-074 — Subdomain: Alternatively, specify the path to massdns using --bin

| Field | Detail |
|:------|--------|
| **Identifier** | F-074 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | puredns |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Valid subdomain discovered: Alternatively, specify the path to massdns using --bin

---

#### F-075 — Subdomain: webmail.leonardtestnew.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-075 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: webmail.leonardtestnew.webgoat via rapiddns

---

#### F-076 — Subdomain: www.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-076 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: www.webgoat via rapiddns

---

#### F-077 — Subdomain: webmail.scottdemo.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-077 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: webmail.scottdemo.webgoat via rapiddns

---

#### F-078 — Subdomain: cpanel.leonardtestnew.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-078 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: cpanel.leonardtestnew.webgoat via rapiddns

---

#### F-079 — Subdomain: www.leonardtestnew.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-079 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: www.leonardtestnew.webgoat via rapiddns

---

#### F-080 — Subdomain: cpanel.leonardtestfriday.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-080 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: cpanel.leonardtestfriday.webgoat via rapiddns

---

#### F-081 — Subdomain: webdisk.acag.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-081 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: webdisk.acag.webgoat via rapiddns

---

#### F-082 — Subdomain: acag.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-082 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: acag.webgoat via rapiddns

---

#### F-083 — Subdomain: mail.leonardtestnew.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-083 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: mail.leonardtestnew.webgoat via rapiddns

---

#### F-084 — Subdomain: webdisk.leonardtestnew.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-084 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: webdisk.leonardtestnew.webgoat via rapiddns

---

#### F-085 — Subdomain: www.acag.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-085 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: www.acag.webgoat via rapiddns

---

#### F-086 — Subdomain: www.leonardtestfriday.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-086 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: www.leonardtestfriday.webgoat via rapiddns

---

#### F-087 — Subdomain: cpanel.acag.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-087 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: cpanel.acag.webgoat via rapiddns

---

#### F-088 — Subdomain: mx.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-088 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: mx.webgoat via rapiddns

---

#### F-089 — Subdomain: leonardtestnew.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-089 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: leonardtestnew.webgoat via rapiddns

---

#### F-090 — Subdomain: webdisk.leonardtestfriday.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-090 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: webdisk.leonardtestfriday.webgoat via rapiddns

---

#### F-091 — Subdomain: www.beta.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-091 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: www.beta.webgoat via rapiddns

---

#### F-092 — Subdomain: donna.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-092 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: donna.webgoat via rapiddns

---

#### F-093 — Subdomain: 220-khan.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-093 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: 220-khan.webgoat via rapiddns

---

#### F-094 — Subdomain: www.donna.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-094 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: www.donna.webgoat via rapiddns

---

#### F-095 — Subdomain: mail.leonardtestfriday.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-095 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: mail.leonardtestfriday.webgoat via rapiddns

---

#### F-096 — Subdomain: www.scottdemo.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-096 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: www.scottdemo.webgoat via rapiddns

---

#### F-097 — Subdomain: webdisk.scottdemo.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-097 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: webdisk.scottdemo.webgoat via rapiddns

---

#### F-098 — Subdomain: ns1.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-098 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: ns1.webgoat via rapiddns

---

#### F-099 — Subdomain: srv1.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-099 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: srv1.webgoat via rapiddns

---

#### F-100 — Subdomain: webmail.acag.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-100 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: webmail.acag.webgoat via rapiddns

---

#### F-101 — Subdomain: ns2.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-101 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: ns2.webgoat via rapiddns

---

#### F-102 — Subdomain: cpanel.scottdemo.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-102 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: cpanel.scottdemo.webgoat via rapiddns

---

#### F-103 — Subdomain: admin.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-103 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: admin.webgoat via rapiddns

---

#### F-104 — Subdomain: beta.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-104 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: beta.webgoat via rapiddns

---

#### F-105 — Subdomain: scottdemo.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-105 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: scottdemo.webgoat via rapiddns

---

#### F-106 — Subdomain: webmail.leonardtestfriday.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-106 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: webmail.leonardtestfriday.webgoat via rapiddns

---

#### F-107 — Subdomain: khan.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-107 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: khan.webgoat via rapiddns

---

#### F-108 — Subdomain: leonardtestfriday.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-108 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: leonardtestfriday.webgoat via rapiddns

---

#### F-109 — Subdomain: mail.scottdemo.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-109 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: mail.scottdemo.webgoat via rapiddns

---

#### F-110 — Subdomain: mail.acag.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-110 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | Unknown |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | — |

**Description**

Discovered subdomain: mail.acag.webgoat via rapiddns

---

## Appendix A — Scan Errors

The following tools encountered errors during the assessment.
These are tool execution failures, not security findings.

| Target | Tool | Error |
|--------|------|-------|
| `https://pentest-ground.com:4280` | `arjun` | Tool timed out after 300s |
| `https://pentest-ground.com:4280` | `cariddi` | Exit code 2: flag provided but not defined: -u Usage of cariddi:   -c int     	Concurrency level. (default 20)   -cache     	Use the .cariddi_cache folder as cache.   -d int     	Delay between a page |
| `https://pentest-ground.com:4280` | `whatweb` | Tool timed out after 300s |
| `https://pentest-ground.com:5013` | `arjun` | Tool timed out after 300s |
| `https://pentest-ground.com:5013` | `cariddi` | Exit code 2: flag provided but not defined: -u Usage of cariddi:   -c int     	Concurrency level. (default 20)   -cache     	Use the .cariddi_cache folder as cache.   -d int     	Delay between a page |
| `https://pentest-ground.com:5013` | `whatweb` | Tool timed out after 300s |
| `https://pentest-ground.com:81` | `arjun` | Tool timed out after 300s |
| `https://pentest-ground.com:81` | `cariddi` | Exit code 2: flag provided but not defined: -u Usage of cariddi:   -c int     	Concurrency level. (default 20)   -cache     	Use the .cariddi_cache folder as cache.   -d int     	Delay between a page |
| `https://pentest-ground.com:81` | `whatweb` | Tool timed out after 300s |
| `https://pentest-ground.com:9000` | `arjun` | Tool timed out after 300s |
| `https://pentest-ground.com:9000` | `cariddi` | Exit code 2: flag provided but not defined: -u Usage of cariddi:   -c int     	Concurrency level. (default 20)   -cache     	Use the .cariddi_cache folder as cache.   -d int     	Delay between a page |
| `https://pentest-ground.com:9000` | `restler` | Binary not found: restler |
| `https://pentest-ground.com:9000` | `whatweb` | Tool timed out after 300s |
| `juice-shop` | `httprobe` | Tool timed out after 300s |
| `webgoat` | `httprobe` | Tool timed out after 300s |

---

## Appendix B — PoC Assets

The following proof-of-concept scripts were generated during analysis.
Execute them **only inside the Docker container** against the isolated target environment.

- `reports/run_20260718_163039/poc/poc-001.py`
- `reports/run_20260718_163039/poc/poc-002.sh`
- `reports/run_20260718_163039/poc/poc-003.sh`
- `reports/run_20260718_163039/poc/poc-004.sh`
- `reports/run_20260718_163039/poc/poc-005.sh`
- `reports/run_20260718_163039/poc/poc-006.py`
- `reports/run_20260718_163039/poc/poc-007.sh`
- `reports/run_20260718_163039/poc/poc-008.sh`
- `reports/run_20260718_163039/poc/poc-009.py`
- `reports/run_20260718_163039/poc/poc-010.py`
- `reports/run_20260718_163039/poc/poc-011.py`
- `reports/run_20260718_163039/poc/poc-012.py`
- `reports/run_20260718_163039/poc/poc-013.sh`
- `reports/run_20260718_163039/poc/poc-014.py`
- `reports/run_20260718_163039/poc/poc-015.py`
- `reports/run_20260718_163039/poc/poc-016.sh`
- `reports/run_20260718_163039/poc/poc-017.py`
- `reports/run_20260718_163039/poc/poc-018.sh`
- `reports/run_20260718_163039/poc/poc-019.py`
- `reports/run_20260718_163039/poc/poc-020.sh`

---


---

*Report generated by vuln-scanner · 2026-07-18 16:57:38 UTC*
