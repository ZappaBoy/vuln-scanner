---

# VULNERABILITY ASSESSMENT REPORT

---

| | |
|:---|:---|
| **Classification** | CONFIDENTIAL |
| **Report Date** | 2026-07-16 |
| **Assessment Type** | Automated Security Scan |
| **Targets Assessed** | 3 |
| **Total Findings** | 53 |
| **Report Version** | 1.0 |

> **CONFIDENTIAL** — This report contains sensitive security information.
> Distribution is restricted to authorized recipients only.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope and Methodology](#scope-and-methodology)
3. [Severity Rating Guide](#severity-rating-guide)
4. [Findings Overview](#findings-overview)
5. [Vulnerability Clusters](#vulnerability-clusters)
6. [Detailed Findings](#detailed-findings)
   - [Target: dvwa](#target-dvwa)
   - [Target: juice-shop](#target-juice-shop)
   - [Target: webgoat](#target-webgoat)

Appendix A — [Scan Errors](#appendix-a--scan-errors)

---

## 1. Executive Summary

The findings are primarily reconnaissance and exposure observations rather than confirmed vulnerabilities. One cluster shows publicly reachable web services on Apache Tomcat and Apache HTTPD across multiple ports, which increases attack surface and should be validated for hardening, patch level, and access restrictions. The second cluster consists of passive subdomain discoveries for several domains, indicating a broader DNS footprint that may reveal additional assets if those hosts resolve and expose services. Overall risk is currently low to informational, but the exposed services and published subdomains warrant follow-up validation to prevent them from becoming actionable entry points.

---

## 2. Scope and Methodology

### 2.1 Assessment Scope

The following targets were included in this assessment:

| # | Target | Type |
|---|--------|------|
| 1 | `dvwa` | HOST |
| 2 | `juice-shop` | HOST |
| 3 | `webgoat` | HOST |

### 2.2 Tools Executed

| Tool | Findings | Status |
|------|:--------:|--------|
| `subfinder` | 45 | Success |
| `nmap` | 4 | Success |
| `rustscan` | 4 | Success |

### 2.3 Scan Configuration

| Parameter | Value |
|-----------|-------|
| Scan duration | 259 seconds |
| Tools run | 29 |
| Tools with errors | 3 |
| Tools skipped (binary not found) | 9 |

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
| 🟠 HIGH | 0 | — |
| 🟡 MEDIUM | 0 | — |
| 🔵 LOW | 0 | — |
| ⚪ INFO | 53 | ████████████████████ |

### 4.2 Findings by Target

| Target | INFO | Total |
|--------|:------:|------:|
| `dvwa` | 3 | **3** |
| `juice-shop` | 3 | **3** |
| `webgoat` | 12 | **12** |

---

## 5. Vulnerability Clusters

### Cluster 1 — Exposed web services and application ports

| | |
|:---|:---|
| **Severity** | ⚪ INFO |
| **Affected Findings** | 12 |
| **Tags** | exposure, web, tomcat, apache, attack-surface |

These findings all indicate TCP ports exposing web-facing services rather than confirmed vulnerabilities. The common root cause is service exposure on Apache Tomcat or Apache HTTPD endpoints without evidence of hardening, access control, or version-specific validation. Further assessment is needed to determine whether any of the exposed applications or configurations introduce real attack paths.

**Shared Remediation**

Confirm the necessity of each exposed service and restrict access with host firewalls, security groups, or reverse proxies. Identify the exact application and version behind each port, remove unused listeners, and apply vendor patches and hardening guidance. Where appropriate, enforce authentication, disable default/sample applications, and perform follow-up web and configuration testing to validate that no sensitive interfaces are exposed.


### Cluster 2 — Passive subdomain and namespace reconnaissance

| | |
|:---|:---|
| **Severity** | ⚪ INFO |
| **Affected Findings** | 14 |
| **Tags** | reconnaissance, dns, subdomain-enumeration, attack-surface, information-disclosure |

These findings stem from passive enumeration of subdomains from public DNS sources. The underlying root cause is the presence of discoverable DNS records that expand the organization’s attack surface, but none of the findings alone prove a reachable service or weakness. They become actionable only if the discovered hosts resolve to live systems with exposed applications, administrative interfaces, or misconfigurations.

**Shared Remediation**

Inventory all externally discoverable subdomains and validate which ones should remain public. Remove stale DNS records, segregate internal or administrative hosts from public DNS, and ensure exposed subdomains use appropriate access controls, authentication, and monitoring. Continuously monitor for newly published records and verify that sensitive services are not inadvertently exposed through DNS.


---

## 6. Detailed Findings

### Target: dvwa

| ID | Severity | Finding | Tool(s) | Confidence |
|----|----------|---------|---------|:----------:|
| F-001 | INFO | Open port 80/tcp — http (Apache httpd 2.4.67) | nmap, rustscan | High |
| F-002 | INFO | Subdomain: img.dvwa | subfinder | High |
| F-003 | INFO | Subdomain: mail.dvwa | subfinder | High |

#### F-001 — Open port 80/tcp — http (Apache httpd 2.4.67)

| Field | Detail |
|:------|--------|
| **Identifier** | F-001 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | 172.20.0.8 |
| **Detected By** | nmap, rustscan |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-1 |

**Description**

Port 80/tcp is open on 172.20.0.8. Service detected: http (Apache httpd 2.4.67).

**Business Impact**

This is not a vulnerability by itself; it indicates a reachable web service on port 80. Exploitability depends entirely on the web application and any Apache or application-layer misconfigurations or flaws discovered during further testing.

**Analyst Note**

> Informational finding only: Apache httpd 2.4.67 is listening on TCP/80. No CVE or misconfiguration is demonstrated by the scan output, so this should be treated as service discovery rather than a security issue.

**Short-term Mitigation**

1. **Restrict exposure immediately**: If the HTTP service is not required, block inbound access to **172.20.0.8:80/tcp** at the host firewall, security group, or upstream network ACL.

```bash
# Example using UFW
sudo ufw deny 80/tcp
sudo ufw reload

# Example using iptables
sudo iptables -A INPUT -p tcp --dport 80 -j DROP
```

2. **Limit access to trusted sources**: If the service must remain available, temporarily allow only approved administrative or application subnets.

```bash
# Example: allow only a management subnet
sudo ufw allow from 10.10.10.0/24 to any port 80 proto tcp
sudo ufw deny 80/tcp
```

3. **Place behind a reverse proxy or WAF**: If public access is not required, front the service with a controlled gateway and restrict direct access to the backend Apache host.

4. **Disable unnecessary virtual hosts or applications**: Remove any nonessential sites, sample content, default pages, or staging applications that may be exposed on port 80.

5. **Confirm no sensitive content is exposed**: Review the site for default pages, directory listings, debug endpoints, backup files, and administrative interfaces, and remove any immediately exposed sensitive resources.

6. **Increase monitoring**: Enable access logging and alerting for unusual request patterns, repeated 404s, directory traversal indicators, or POST requests to unexpected paths.

```apache
# Example Apache logging
CustomLog logs/access_log combined
ErrorLog logs/error_log
```

7. **Verify version and patch status**: Apache httpd 2.4.67 should be assessed against current vendor advisories and package updates; if the service cannot be patched immediately, reduce exposure using the controls above.

**Permanent Remediation**

1. **Confirm business requirement for HTTP service**: Determine whether port **80/tcp** is needed at all. If the application has no legitimate need for cleartext HTTP, retire the listener and expose only the required service endpoints.

2. **Enforce least-exposure network design**: Implement firewall rules so Apache is reachable only from the networks that require it. Prefer deny-by-default policies and document allowed sources.

```bash
# Example nftables policy allowing only a trusted subnet
nft add rule inet filter input ip saddr 10.10.10.0/24 tcp dport 80 accept
nft add rule inet filter input tcp dport 80 drop
```

3. **Migrate to HTTPS**: If the service is externally or internally consumed, terminate TLS on **443/tcp** and redirect HTTP to HTTPS. Use valid certificates and disable plaintext-only access where feasible.

```apache
# Example redirect from HTTP to HTTPS
<VirtualHost *:80>
    ServerName example.internal
    Redirect permanent / https://example.internal/
</VirtualHost>
```

4. **Harden Apache httpd configuration**: Apply secure baseline settings to reduce attack surface and limit information disclosure.

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
Options -Indexes
```

5. **Remove or isolate unnecessary modules and content**: Disable unused Apache modules, sample applications, and default documents. Segment administrative applications onto separate virtual hosts, hosts, or networks.

```bash
# Debian/Ubuntu example: disable an unused module
sudo a2dismod status
sudo systemctl reload apache2
```

6. **Patch and maintain Apache and dependencies**: Upgrade Apache httpd and related libraries to the latest vendor-supported release. Establish routine patch management to address future CVEs promptly.

```bash
# Example package update workflow
sudo apt update
sudo apt upgrade apache2
```

7. **Implement secure application controls**: Review the web application for authentication, authorization, input validation, CSRF protections, and secure session handling. Fix any issues identified during application-layer testing, since the open port itself is only an entry point.

8. **Add operational safeguards**: Deploy centralized logging, file integrity monitoring, vulnerability scanning, and periodic review of exposed services. Re-scan after remediation to confirm that only approved services remain reachable.

9. **Validate the final state**: Confirm that port 80 is closed if not required, or that it only redirects to HTTPS and serves no sensitive content. Document the approved exposure and keep firewall and Apache configurations under change control.

---

#### F-002 — Subdomain: img.dvwa

| Field | Detail |
|:------|--------|
| **Identifier** | F-002 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | dvwa |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: img.dvwa via rapiddns

**Business Impact**

This is not directly exploitable by itself; it is only evidence that a subdomain exists. Exploitability depends entirely on whether img.dvwa resolves to a live service with a vulnerable application or misconfiguration.

**Analyst Note**

> Informational subdomain discovery from subfinder via rapiddns. No vulnerability is demonstrated and no CVE is associated. Treat as reconnaissance data only unless the subdomain hosts an exposed service worth assessing.

**Short-term Mitigation**

1. **Verify exposure**: Confirm whether `img.dvwa` currently resolves in public DNS and whether it serves any application or static content.
2. **Reduce unnecessary visibility**: If the subdomain is not required, temporarily remove or disable the DNS record until ownership and purpose are confirmed.
3. **Restrict access**: If the host is required but not meant for public use, place it behind network controls such as a VPN, IP allowlist, or firewall rules.
4. **Disable nonessential services**: Shut down any unnecessary web services, test instances, or preview deployments on the host until a proper security review is completed.
5. **Apply temporary hardening**: Ensure the server is patched, default accounts are removed, and directory listing is disabled.
6. **Monitor for abuse**: Review web server, DNS, and access logs for unexpected traffic to `img.dvwa` and alert on anomalous requests.
7. **Document ownership**: Assign an application owner and operational contact so the subdomain can be tracked and remediated promptly.

Example verification commands:
```bash
nslookup img.dvwa
curl -I http://img.dvwa
```

Example temporary access control concept:
```nginx
location / {
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;
}
```

**Permanent Remediation**

1. **Confirm asset legitimacy**: Validate whether `img.dvwa` is an approved subdomain and map it to an owner, purpose, and data classification.
2. **Inventory and register**: Add the subdomain to the official asset inventory, CMDB, or DNS governance process so it is tracked going forward.
3. **Harden DNS management**: Restrict who can create or modify DNS records, require change approval, and review zone updates regularly.
4. **Implement lifecycle controls**: Ensure subdomains are created only through a controlled request process and removed when no longer needed.
5. **Secure the hosted service**: If the subdomain is live, apply baseline web and host hardening, patching, least privilege, secure headers, TLS, and authenticated administrative access.
6. **Segment and isolate**: Host the service in a segmented network or dedicated environment so a compromise does not expose internal systems.
7. **Continuously monitor**: Add the subdomain to vulnerability scanning, certificate monitoring, and DNS monitoring to detect drift, exposure, or unauthorized changes.
8. **Retire unused records**: If `img.dvwa` has no business need, permanently remove the DNS record and any associated backend services, certificates, and routing entries.

Example DNS governance workflow:
```text
Request -> Security review -> Approval -> DNS change -> Validation -> Asset registry update
```

Example removal command for a controlled DNS environment:
```bash
# Remove the DNS record using your authorized DNS management tooling
# Example only; replace with your platform-specific command
```

Example validation after remediation:
```bash
nslookup img.dvwa
curl -I https://img.dvwa
```

---

#### F-003 — Subdomain: mail.dvwa

| Field | Detail |
|:------|--------|
| **Identifier** | F-003 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | dvwa |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: mail.dvwa via rapiddns

**Business Impact**

Very low on its own; discovering a subdomain is reconnaissance information and does not indicate a direct vulnerability. It could only become useful if the subdomain exposes a misconfiguration or vulnerable service, which is not shown here.

**Analyst Note**

> This is an informational subdomain enumeration result from subfinder/rapiddns. There is no evidence of exposed functionality, misconfiguration, or impact beyond asset discovery, so it should not be treated as a security issue by itself.

**Short-term Mitigation**

1. **Validate the subdomain**: Confirm whether `mail.dvwa` is an intended and active service. If it is not required, temporarily **disable DNS resolution** or remove any public-facing references to reduce further discovery.
2. **Restrict exposure**: If the subdomain must remain available, place it behind **network controls** such as a VPN, IP allowlist, firewall rules, or reverse-proxy authentication to limit access while it is reviewed.
3. **Reduce reconnaissance value**: Remove unnecessary information leakage from the host, including **banner details**, verbose error pages, and directory listings.
4. **Harden the service quickly**: Apply current patches to the mail stack and ensure secure defaults are enabled (TLS, strong auth, disabled anonymous access where applicable).
5. **Review DNS records**: Check for unintended records such as stale `A`, `AAAA`, `CNAME`, `MX`, or wildcard entries that expose internal or deprecated infrastructure.
6. **Monitor for abuse**: Enable logging and alerting on the subdomain to detect unexpected requests, brute-force attempts, or enumeration activity.

```bash
# Example: verify DNS records and identify stale entries
nslookup mail.dvwa

# Example: temporarily restrict access at a reverse proxy or firewall
# Allow only trusted management IPs
iptables -A INPUT -p tcp --dport 443 -s 203.0.113.10 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j DROP
```

**Permanent Remediation**

1. **Inventory and ownership**: Establish whether `mail.dvwa` is a business-required service. Assign an owner, document its purpose, and classify whether it is meant to be public, internal-only, or retired.
2. **Remove or retire unused subdomains**: If the subdomain is not needed, **delete the DNS record** and decommission the underlying host, application, or mail service to eliminate the attack surface.
3. **Secure the mail service**: If the subdomain is required, apply a full hardening baseline:
   - Keep the mail server and dependencies **fully patched**.
   - Enforce **TLS 1.2+ / 1.3** and disable weak ciphers.
   - Require **authenticated access**; disable anonymous SMTP relay, default accounts, and legacy protocols where possible.
   - Apply **rate limiting**, lockout controls, and anti-brute-force protections.
4. **Minimize DNS exposure**: Publish only the records necessary for operation. Avoid exposing internal hostnames, development endpoints, or unnecessary aliases. Review SPF, DKIM, and DMARC configuration to ensure mail infrastructure is intentional and properly controlled.
5. **Implement segmentation and access control**: Place the mail service in a restricted network zone, expose only required ports, and use a reverse proxy or mail gateway where appropriate. Limit administrative interfaces to trusted management networks.
6. **Harden host and application configuration**: Disable unnecessary services, remove default content, hide version banners, and ensure web/mail admin consoles are not accessible from the public internet unless explicitly required.
7. **Create a subdomain lifecycle process**: Add a formal workflow for provisioning, reviewing, and decommissioning subdomains so stale DNS entries are not left behind.
8. **Continuous monitoring and reassessment**: Add the subdomain to asset inventory, vulnerability scanning, and log monitoring. Periodically review whether it remains necessary and whether its exposure still matches policy.

```bash
# Example: remove an unused DNS record from a BIND zone file
mail    IN    A     192.0.2.25
# delete the record, then reload DNS
rndc reload

# Example: verify mail-related security settings (illustrative)
# Ensure only TLS-capable services are enabled and legacy protocols are disabled
ss -tulpn | grep -E ':(25|465|587|993|995)\b'
```

---

### Target: juice-shop

| ID | Severity | Finding | Tool(s) | Confidence |
|----|----------|---------|---------|:----------:|
| F-004 | INFO | Open port 3000/tcp — ppp | nmap | High |
| F-005 | INFO | Subdomain: mail.juice-shop | subfinder | High |
| F-006 | INFO | Subdomain: www.juice-shop | subfinder | High |

#### F-004 — Open port 3000/tcp — ppp

| Field | Detail |
|:------|--------|
| **Identifier** | F-004 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | 172.20.0.3 |
| **Detected By** | nmap |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-1 |

**Description**

Port 3000/tcp is open on 172.20.0.3. Service detected: ppp.

**Business Impact**

Low by itself: this is only an open TCP port with an identified service, not a vulnerability. Exploitability depends entirely on what application is listening on 3000/tcp and whether it has an actual weakness.

**Analyst Note**

> Informational finding only. Port 3000 is commonly used by web apps and development services; 'ppp' is likely an imprecise service fingerprint from nmap rather than a confirmed protocol. No CVE or misconfiguration is established from the scan alone.

**Short-term Mitigation**

1. **Identify the listening process** on `172.20.0.3:3000` immediately to confirm whether the service is expected and to determine exposure scope.
   ```bash
   sudo ss -ltnp | grep ':3000'
   sudo lsof -iTCP:3000 -sTCP:LISTEN -Pn
   ```

2. **Restrict network access** to port `3000/tcp` at the host, container, or network firewall until the service is verified.
   ```bash
   sudo ufw deny 3000/tcp
   # or, if using iptables
   sudo iptables -A INPUT -p tcp --dport 3000 -j DROP
   ```

3. **Limit exposure to trusted sources only** if the service must remain temporarily available. Allow only specific management IPs, a VPN subnet, or an internal security group.
   ```bash
   sudo iptables -A INPUT -p tcp -s 10.0.0.0/24 --dport 3000 -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 3000 -j DROP
   ```

4. **If the service is non-essential, stop it immediately** to eliminate the exposure while validation is performed.
   ```bash
   sudo systemctl stop <service-name>
   sudo systemctl disable <service-name>
   ```

5. **Place the application behind a reverse proxy or access gateway** if remote access is required, enforcing authentication, rate limiting, and TLS at the edge rather than exposing `3000/tcp` directly.

6. **Monitor logs and connection attempts** for the port to determine whether the service is being actively used or probed.
   ```bash
   sudo journalctl -u <service-name> --since '24 hours ago'
   sudo tcpdump -ni any tcp port 3000
   ```

7. **Document the business justification** for the open port and assign ownership so the service is not left exposed without an accountable system owner.

**Permanent Remediation**

1. **Perform a full service identification and risk assessment** for the application bound to `3000/tcp`.
   - Determine the exact daemon, version, startup mechanism, and whether it is intended to be reachable from the network.
   - Validate whether the service is a development interface, admin console, API endpoint, or a production dependency.
   - Review the application’s authentication, authorization, and transport security controls.

2. **Remove unnecessary network exposure** by binding the service to localhost or an internal interface only if remote access is not required.
   ```ini
   # Example application binding
   HOST=127.0.0.1
   PORT=3000
   ```
   If the service is running in a container, publish the port only to the loopback interface or an internal network.
   ```bash
   docker run -p 127.0.0.1:3000:3000 <image>
   ```

3. **Enforce least-privilege network controls** at the host, orchestration, and perimeter layers.
   - Add explicit allowlists for approved clients.
   - Deny all other inbound traffic to `3000/tcp`.
   - In Kubernetes or similar platforms, use NetworkPolicies or security groups to restrict access.
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: allow-only-trusted-clients
   spec:
     podSelector:
       matchLabels:
         app: my-app
     policyTypes:
       - Ingress
     ingress:
       - from:
           - ipBlock:
               cidr: 10.0.0.0/24
         ports:
           - protocol: TCP
             port: 3000
   ```

4. **Place the service behind a hardened reverse proxy or API gateway** if external access is required.
   - Terminate TLS at the proxy.
   - Require authentication and authorization.
   - Add request throttling, size limits, and logging.
   - Disable direct exposure of the backend port to the network.

5. **Harden the application itself** if it is a web service or API.
   - Remove default credentials and unauthenticated administrative endpoints.
   - Patch to a supported version.
   - Disable debug, dev, or test modes.
   - Ensure sensitive endpoints are protected by role-based access control.
   - Validate that only intended protocols and methods are permitted.

6. **Implement secure service management** so the port state is controlled by configuration rather than ad hoc changes.
   - Create a documented systemd unit, container manifest, or orchestration manifest.
   - Ensure the service starts only on approved hosts.
   - Use configuration management to prevent drift.
   ```ini
   [Unit]
   Description=My Service
   After=network.target

   [Service]
   ExecStart=/opt/myapp/bin/myapp --host 127.0.0.1 --port 3000
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

7. **Add continuous validation and alerting** for unexpected listening ports.
   - Baseline approved ports per host role.
   - Alert on new or changed listeners.
   - Include `3000/tcp` in routine vulnerability and configuration compliance checks.

8. **Document the approved use case and ownership** for any service that must remain on `3000/tcp`.
   - Record the application name, owner, data classification, and justification.
   - Define review dates and decommission criteria.
   - Reassess the port during change management and patch cycles.

9. **Verify remediation after implementation**.
   - Confirm the service is no longer exposed externally or is accessible only from approved sources.
   - Re-scan the host and validate firewall rules.
   ```bash
   nmap -p 3000 172.20.0.3
   sudo ss -ltnp | grep ':3000' || true
   ```

---

#### F-005 — Subdomain: mail.juice-shop

| Field | Detail |
|:------|--------|
| **Identifier** | F-005 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: mail.juice-shop via rapiddns

**Business Impact**

Low. This is passive subdomain discovery from public DNS data and does not indicate a vulnerability by itself; exploitation would require an associated misconfiguration or exposed service on the discovered host.

**Analyst Note**

> Informational asset discovery only. 'mail.juice-shop' appears to be a hostname returned by OSINT sources and does not demonstrate impact without further validation of DNS resolution, service exposure, or trust relationships.

**Short-term Mitigation**

1. **Validate the asset**: Confirm whether **mail.juice-shop** is an intended, authorized host and document its business purpose, owner, and exposed services.
2. **Restrict exposure if not required**: If the subdomain is not meant to be publicly reachable, remove or suspend its public DNS record and/or place it behind **VPN**, **allowlisting**, or a **reverse proxy** with access controls.
3. **Harden the service immediately**: If the host is required, ensure only the minimum necessary ports are open and disable any unnecessary listeners, admin panels, test endpoints, or default services.
4. **Apply TLS and secure headers**: Ensure the subdomain uses a valid certificate and enforces **HTTPS-only** access where applicable.
5. **Review authentication and default access**: Verify there are no default credentials, anonymous access, directory listing, or permissive CORS settings on the mail service or related web interface.
6. **Monitor for abuse**: Add the host to logging and alerting to detect unexpected connections, brute-force attempts, or service enumeration.
7. **Check for shadow IT dependencies**: Identify whether any email, SMTP, IMAP, or webmail functionality is unintentionally exposed and temporarily disable it if it is not actively needed.

```bash
# Example: verify which services are exposed on the host
nmap -Pn -sT -sV -p- mail.juice-shop

# Example: block public access at the edge if the host is not needed
# (Illustrative firewall concept; adapt to your environment)
ufw deny in on eth0 to any port 25,465,587,80,443
```

8. **Re-scan after changes**: Re-run passive and active checks to confirm the subdomain is no longer publicly exposed or only exposes the intended service set.

**Permanent Remediation**

1. **Establish asset ownership and lifecycle management**: Add **mail.juice-shop** to the official asset inventory with an assigned owner, environment tag, purpose, and decommission date if applicable.
2. **Define DNS governance**: Implement a controlled process for creating, modifying, and removing subdomains, including approval requirements and periodic review of DNS zones for stale records.
3. **Remove or correct unnecessary DNS records**: If the subdomain is not required, delete the record from authoritative DNS and verify that related aliases, CNAMEs, and wildcard entries do not recreate exposure.
4. **Segregate email infrastructure**: If the subdomain supports mail services, host it on a dedicated, hardened mail platform separated from general web applications and production test systems.
5. **Enforce network-layer controls**: Restrict access to administrative and mail protocols using firewalls, security groups, or private connectivity so that only intended sources can reach the service.
6. **Harden the mail stack**: Apply vendor security baselines, disable legacy protocols, enforce strong authentication, and ensure services such as SMTP, IMAP, POP3, and webmail are configured securely.
7. **Implement continuous exposure monitoring**: Add recurring external attack-surface scans and DNS enumeration checks to detect newly published subdomains, stale records, and unintended service exposure.
8. **Centralize certificate and DNS management**: Use automation to provision, renew, and revoke certificates and DNS records through controlled pipelines with peer review.
9. **Document and test decommissioning procedures**: When a subdomain is retired, ensure DNS records, certificates, load balancer entries, firewall rules, and application configurations are all removed together.
10. **Set alerting for unauthorized DNS changes**: Integrate DNS change events into SIEM/monitoring so that unexpected subdomain creation or modification is investigated promptly.

```bash
# Example: remove a stale DNS record (provider-specific command placeholders)
# aws route53 change-resource-record-sets --hosted-zone-id ZONEID --change-batch file://delete-mail-record.json

# Example: verify the subdomain no longer resolves
nslookup mail.juice-shop
```

11. **Perform a post-change validation**: After implementing the permanent fix, confirm from an external vantage point that the record is absent or that the service is intentionally restricted and securely configured.

---

#### F-006 — Subdomain: www.juice-shop

| Field | Detail |
|:------|--------|
| **Identifier** | F-006 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | juice-shop |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: www.juice-shop via rapiddns

**Business Impact**

Low; this is passive subdomain discovery and does not by itself indicate a vulnerability. It only becomes actionable if the subdomain resolves to an exposed service with additional weaknesses.

**Analyst Note**

> Informational finding only. The subdomain was identified via public DNS intelligence and does not demonstrate impact on its own. No CWE applies unless follow-on issues are found on the discovered host.

**Short-term Mitigation**

1. **Validate the subdomain**: Confirm whether `www.juice-shop` is intended to be publicly reachable and whether it currently resolves to an active host, load balancer, or virtual host.
2. **Restrict exposure if not required**: If the subdomain is not meant to be publicly accessible, temporarily block it at the edge (DNS, reverse proxy, or firewall) until its purpose is confirmed.
3. **Serve a safe default response**: If the hostname must remain resolvable, configure the web server or CDN to return a non-sensitive generic page or `404/403` for unapproved hostnames.
4. **Review active services behind the host**: Check for unintended applications, admin panels, test environments, or outdated virtual hosts exposed under `www.juice-shop`.
5. **Monitor access logs**: Enable heightened logging on DNS, reverse proxy, and web server layers to detect probing, unexpected traffic, or host-header misuse.
6. **Document ownership**: Assign an owner for the subdomain and record whether it is production, staging, or deprecated.

Example NGINX host-based deny rule:
```nginx
server {
    listen 80;
    server_name www.juice-shop;
    return 404;
}
```

Example DNS temporary control:
```bash
# Remove or suspend the public DNS record until validation is complete
# (performed in your DNS provider or IaC workflow)
```


**Permanent Remediation**

1. **Inventory and classify the subdomain**: Add `www.juice-shop` to the authoritative asset inventory, marking its business purpose, environment, and owner. Remove any ambiguity about whether it is production, testing, or legacy infrastructure.
2. **Enforce least exposure**: If the subdomain is unnecessary, permanently decommission it by removing DNS records, disabling associated virtual hosts, and revoking any certificates or routes tied to it.
3. **Harden web-server host handling**: Configure all front-end services to use explicit `server_name`/virtual host allowlists and reject unknown host headers by default.
4. **Apply secure DNS and routing controls**: Ensure DNS entries point only to approved infrastructure. Use split-horizon DNS or internal-only resolution for non-public environments.
5. **Standardize deployment controls**: Manage subdomain creation through infrastructure-as-code and change control so new hostnames cannot be published without review and approval.
6. **Implement continuous asset discovery**: Integrate subdomain enumeration into routine monitoring and compare results against the approved inventory to detect rogue or forgotten hostnames.
7. **Validate security posture of any active service**: If `www.juice-shop` is intended to host an application, perform a separate security review covering TLS configuration, authentication, access controls, patching, and common web vulnerabilities.
8. **Retire legacy endpoints**: If the hostname was used for a previous application, fully remove backend mappings, storage, and credentials to prevent accidental reuse or shadow exposure.

Example NGINX default-deny virtual host configuration:
```nginx
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;
    return 444;
}

server {
    listen 80;
    server_name www.juice-shop;
    return 301 https://juice-shop.example.com$request_uri;
}
```

Example DNS/IaC lifecycle control:
```hcl
resource "aws_route53_record" "juice_shop_www" {
  zone_id = var.zone_id
  name    = "www.juice-shop"
  type    = "A"
  ttl     = 300
  records = [var.lb_ip]
}
```

Operationally, the permanent fix is to ensure the hostname is either fully removed or explicitly approved, protected, and monitored as part of the organization’s managed asset baseline.

---

### Target: webgoat

| ID | Severity | Finding | Tool(s) | Confidence |
|----|----------|---------|---------|:----------:|
| F-007 | INFO | Open port 8080/tcp — http (Apache Tomcat ) | nmap, rustscan | High |
| F-008 | INFO | Open port 9090/tcp — http (Apache Tomcat ) | rustscan | High |
| F-009 | INFO | Subdomain: srv1.webgoat | subfinder | High |
| F-010 | INFO | Subdomain: scottdemo.webgoat | subfinder | High |
| F-011 | INFO | Subdomain: leonardtestnew.webgoat | subfinder | High |
| F-012 | INFO | Subdomain: beta.webgoat | subfinder | High |
| F-013 | INFO | Subdomain: webdisk.acag.webgoat | subfinder | High |
| F-014 | INFO | Subdomain: webmail.leonardtestnew.webgoat | subfinder | High |
| F-015 | INFO | Subdomain: ns2.webgoat | subfinder | High |
| F-016 | INFO | Subdomain: cpanel.scottdemo.webgoat | subfinder | High |
| F-017 | INFO | Subdomain: donna.webgoat | subfinder | High |
| F-018 | INFO | Subdomain: 220-khan.webgoat | subfinder | High |

#### F-007 — Open port 8080/tcp — http (Apache Tomcat )

| Field | Detail |
|:------|--------|
| **Identifier** | F-007 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | 172.20.0.7 |
| **Detected By** | nmap, rustscan |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-1 |

**Description**

Port 8080/tcp is open on 172.20.0.7. Service detected: http (Apache Tomcat ).

**Business Impact**

No exploitation is implied by the finding itself; it only confirms an Apache Tomcat service is reachable on TCP/8080. Any real risk depends on the specific Tomcat version, deployed applications, authentication state, and misconfigurations.

**Analyst Note**

> This is an informational exposure finding, not a vulnerability. Port 8080 open on a Tomcat instance is common for web apps, but it increases attack surface and should be reviewed for versioning, default apps, management interfaces, and access controls.

**Short-term Mitigation**

1. **Confirm exposure scope**: Verify whether `172.20.0.7:8080/tcp` is intended to be reachable from the current network segment. If Tomcat is only meant for local or internal administration, treat it as an unnecessary exposure and restrict access immediately.
2. **Restrict network access**: Apply an emergency firewall or security-group rule to allow `8080/tcp` only from approved management hosts, application tiers, or VPN ranges.

```bash
# Example using iptables: allow only a trusted admin subnet
iptables -A INPUT -p tcp -s 10.10.10.0/24 --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

3. **Limit to localhost if possible**: If Tomcat is used only by a local reverse proxy or a co-located application, bind it to `127.0.0.1` or the internal interface only.

```xml
<!-- conf/server.xml: bind connector to loopback -->
<Connector address="127.0.0.1" port="8080" protocol="HTTP/1.1" />
```

4. **Place behind a reverse proxy/WAF**: If external access is required, expose Tomcat only through a hardened reverse proxy (for example, NGINX/Apache) with TLS, access controls, and request filtering.
5. **Disable or remove unused applications**: Remove sample apps, test apps, and any management endpoints not required for current operations.
6. **Verify authentication controls**: Ensure any administrative interfaces, manager apps, or custom applications require strong authentication and are not anonymously accessible.
7. **Check for known vulnerabilities**: Identify the exact Tomcat version and quickly assess whether it is affected by any critical CVEs; if so, prioritize patching or temporary isolation.
8. **Monitor for abuse**: Enable/confirm logging on the host and reverse proxy, and watch for repeated access attempts, unusual request patterns, or unexpected source addresses.

**Permanent Remediation**

1. **Inventory and baseline the service**: Determine the exact Tomcat version, installation source, deployed applications, connector configuration, and whether `8080/tcp` is required for business operation.
2. **Upgrade Tomcat to a supported release**: Move to the latest vendor-supported Apache Tomcat version that is approved by your environment and compatible with the application stack. Apply current security updates and establish a patch cadence.
3. **Reduce exposed surface area**: Reconfigure Tomcat so it is not directly reachable from untrusted networks unless absolutely necessary.

```xml
<!-- conf/server.xml: bind to a private interface or localhost -->
<Connector address="127.0.0.1" port="8080" protocol="HTTP/1.1"
           connectionTimeout="20000"
           redirectPort="8443" />
```

If external service is needed, front Tomcat with a reverse proxy and keep the Tomcat connector private.
4. **Enforce TLS externally**: Terminate HTTPS at the reverse proxy or configure secure connectors so credentials and session data are never sent in cleartext over the network.
5. **Harden authentication and authorization**: Require strong, unique credentials for administrative access; integrate with centralized identity management where possible; remove default accounts; and ensure manager/admin applications are restricted to approved roles and IP ranges.
6. **Remove unnecessary components**: Delete sample, documentation, example, and test applications from production deployments. Disable modules and endpoints not required by the application.
7. **Apply secure configuration settings**: Review `server.xml`, deployed application descriptors, and JVM/system settings for insecure defaults. Disable directory listings, verbose error pages, and unnecessary HTTP methods.
8. **Implement host and network controls**: Maintain host-based firewall rules and upstream ACLs so the service is only reachable from approved sources. Add segmentation if the service is in a shared subnet.
9. **Add continuous vulnerability management**: Include Tomcat in routine configuration scanning and patch management. Track version drift and revalidate exposure after every deployment or infrastructure change.
10. **Establish logging and alerting**: Centralize Tomcat access/error logs and alert on authentication failures, repeated 4xx/5xx responses, unusual user agents, and unexpected remote hosts.
11. **Validate the fix**: After changes, rescan the target and confirm that `8080/tcp` is either closed or reachable only from authorized systems, and that any remaining access is protected by authentication and TLS.

```bash
# Example validation checks
ss -ltnp | grep ':8080'
nmap -sV -p 8080 172.20.0.7
```

12. **Document and operationalize**: Record the approved exposure model for Tomcat, the owners of the service, and the required review steps for future deployments so the port is not re-exposed inadvertently.

---

#### F-008 — Open port 9090/tcp — http (Apache Tomcat )

| Field | Detail |
|:------|--------|
| **Identifier** | F-008 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | 172.20.0.7 |
| **Detected By** | rustscan |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-1 |

**Description**

Port 9090/tcp is open on 172.20.0.7. Service: http (Apache Tomcat ).

**Business Impact**

Very low; this is only an exposed TCP/HTTP service identification on port 9090 with no vulnerability evidence. Exploitation would require a separate Tomcat misconfiguration or known CVE, none of which are indicated here.

**Analyst Note**

> Informational finding only. The scan confirms port 9090 is open and appears to run Apache Tomcat, but no weakness, version, or accessible endpoint was identified, so this is not a security issue by itself.

**Short-term Mitigation**

1. **Restrict network exposure immediately**: If Tomcat on **9090/tcp** is not required for external access, block it at the host firewall, security group, or network ACL so only trusted administrative sources can reach it.

   ```bash
   # Example: block inbound TCP/9090 on Linux (iptables)
   iptables -A INPUT -p tcp --dport 9090 -j DROP
   ```

2. **Limit access to trusted IPs/VPN only**: If the service must remain available short-term, allow traffic only from approved management networks, jump hosts, or VPN ranges.

   ```bash
   # Example: allow only a trusted subnet and deny everyone else
   iptables -A INPUT -p tcp -s 10.10.0.0/24 --dport 9090 -j ACCEPT
   iptables -A INPUT -p tcp --dport 9090 -j DROP
   ```

3. **Verify what is listening on the port**: Confirm the process, container, or reverse proxy bound to **172.20.0.7:9090** and determine whether it is required.

   ```bash
   ss -ltnp | grep ':9090'
   lsof -iTCP:9090 -sTCP:LISTEN -n -P
   ```

4. **Reduce immediate attack surface**: If this is Tomcat’s management or administrative interface, disable any unused management applications, sample apps, or remote administration features until a proper hardening review is completed.

5. **Monitor for unexpected access**: Review logs for inbound connections to **9090/tcp** and alert on any access outside authorized sources.

   ```bash
   journalctl -u tomcat --since '24 hours ago'
   ```

**Permanent Remediation**

1. **Determine business requirement**: Confirm whether Apache Tomcat on **9090/tcp** is necessary. If it is not required, remove the exposure entirely by stopping the service, disabling the listener, and preventing it from starting at boot.

   ```bash
   systemctl stop tomcat
   systemctl disable tomcat
   ```

2. **Bind Tomcat to a private interface or localhost**: If Tomcat must remain active, configure it to listen only on a non-routable interface or loopback, or place it behind a reverse proxy that exposes only approved endpoints.

   ```xml
   <!-- Example server.xml connector bound to localhost -->
   <Connector port="9090" protocol="HTTP/1.1"
              address="127.0.0.1"
              connectionTimeout="20000"
              redirectPort="8443" />
   ```

3. **Enforce network segmentation**: Place the service in a restricted management network or internal VLAN and ensure routing/firewall policy prevents direct access from untrusted networks. Only required application tiers or admin jump hosts should be permitted.

4. **Harden Tomcat configuration**: Remove or disable default apps, manager/host-manager interfaces, and any unnecessary examples. Ensure the server is not exposing version banners or debug endpoints, and confirm that directory listings and test applications are not accessible.

5. **Implement authentication and authorization controls**: If administration is required, restrict it with strong authentication, role-based access, and IP allowlisting. Prefer centralized identity integration and multi-factor authentication for administrative access.

6. **Upgrade and patch Tomcat regularly**: Keep Apache Tomcat and the Java runtime at supported, vendor-patched versions. Establish a patch cadence and verify that security updates are applied promptly to reduce the risk of future CVE exposure.

   ```bash
   # Example validation commands
   catalina.sh version
   java -version
   ```

7. **Use TLS for any required remote access**: If the service must be reachable over a network, terminate HTTPS with a valid certificate and disable cleartext HTTP where possible. Ensure weak ciphers and legacy protocols are disabled.

8. **Add continuous asset and port monitoring**: Integrate host and network monitoring to detect unexpected listeners on **9090/tcp**, configuration drift, and unauthorized exposure. Alert on new services bound to externally reachable interfaces.

9. **Document and test the exposure controls**: Record the approved access model for the service, validate firewall and Tomcat binding settings after every change, and include the port in routine vulnerability and configuration compliance checks.

10. **Re-scan to verify closure**: After changes, confirm that **9090/tcp** is no longer exposed externally or is only reachable from approved sources.

   ```bash
   rustscan -a 172.20.0.7 -p 9090
   ```

---

#### F-009 — Subdomain: srv1.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-009 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: srv1.webgoat via rapiddns

**Business Impact**

This is only passive subdomain discovery, so there is no direct exploit path from the finding itself. Any risk depends on whether the discovered host resolves, is reachable, and exposes vulnerable services or sensitive admin interfaces.

**Analyst Note**

> Info-only reconnaissance result from subfinder/rapiddns. The presence of srv1.webgoat indicates possible additional attack surface, but this finding alone is not a vulnerability and should be treated as asset inventory data.

**Short-term Mitigation**

1. **Validate the host**: Confirm whether `srv1.webgoat` currently resolves in DNS and whether it is reachable from untrusted networks. If it is not required, **remove or disable the DNS record** immediately.
2. **Restrict exposure**: If the subdomain must remain active, place it behind **access controls** such as VPN, IP allowlisting, or authentication at the reverse proxy/WAF layer.
3. **Review services for sensitive interfaces**: Check the host for exposed admin consoles, debug endpoints, default pages, or management ports. Temporarily **block unnecessary ports** at the firewall/security group level.
4. **Limit information disclosure**: Ensure banners, version strings, and directory listings are disabled on any web services running on the host.
5. **Monitor for access**: Enable logging and alerting for DNS queries, HTTP/S requests, and authentication failures to detect reconnaissance or abuse.
6. **Short-term containment example**: If the service should only be used internally, restrict access to internal networks only.

```bash
# Example: firewall allowlist for internal network only
iptables -A INPUT -p tcp --dport 80 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j DROP
iptables -A INPUT -p tcp --dport 443 -j DROP
```


**Permanent Remediation**

1. **Inventory and ownership**: Assign an owner to `srv1.webgoat` and document its purpose, required users, backend services, and data classification.
2. **Determine necessity**: If the subdomain is no longer required, **decommission it fully** by removing the DNS record, shutting down associated infrastructure, and revoking certificates or credentials tied to the host.
3. **Harden DNS management**: Maintain an authoritative inventory of approved subdomains and implement change control so new records cannot be created without review.
4. **Apply least exposure by design**: For any required service, place it behind an authenticated access layer, network segmentation, and only the minimum ports needed for operation.
5. **Harden the host and applications**: Patch the OS and services, remove unused software, disable default accounts, enforce strong authentication, and ensure TLS is configured correctly.
6. **Protect administrative interfaces**: Move admin panels off public DNS where possible; otherwise restrict them to VPN, bastion hosts, or private network ranges and require MFA.
7. **Implement continuous external attack surface monitoring**: Periodically scan for new or changed subdomains, open ports, and exposed services. Alert on unapproved findings.
8. **Document and test decommissioning procedures**: Ensure removed DNS records do not leave dangling hosts or orphaned certificates that could be re-claimed later.
9. **Example DNS cleanup**: Remove the record in the zone file or DNS provider console.

```dns
; Example BIND zone removal
;srv1.webgoat.    IN    A     203.0.113.10
;srv1.webgoat.    IN    AAAA  2001:db8::10
```

10. **Verification after remediation**: Re-run subdomain enumeration and confirm the host no longer resolves or, if retained, that it is only reachable under the approved access controls.

```bash
subfinder -d webgoat -silent
nslookup srv1.webgoat
curl -I https://srv1.webgoat
```

---

#### F-010 — Subdomain: scottdemo.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-010 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: scottdemo.webgoat via rapiddns

**Business Impact**

This is a passive recon finding only. Enumerating a subdomain does not provide a direct attack path by itself; exploitation would depend on whether the host resolves and exposes a vulnerable service, misconfiguration, or sensitive content.

**Analyst Note**

> Subfinder/rapiddns discovered scottdemo.webgoat as part of public DNS/subdomain enumeration. This is informational and not a vulnerability unless the subdomain hosts an exposed asset with additional issues. The raw output suggests multiple related subdomains, so the main value is attack surface discovery.

**Short-term Mitigation**

1. **Validate ownership and necessity** of `scottdemo.webgoat` immediately. Confirm whether this subdomain is intentionally published and which team owns it.
2. **Restrict exposure if not required** by removing or pausing the DNS record until its purpose is confirmed.
3. **Limit access at the edge** using temporary controls such as IP allowlisting, basic authentication, or a WAF rule if the host must remain online.
4. **Disable non-essential services** on the host and confirm that no administrative, staging, or debug interfaces are publicly accessible.
5. **Review the content served** by the subdomain for sensitive data, environment details, or test functionality that should not be public.
6. **Monitor logs and alerts** for requests to the subdomain to identify unexpected scanning or abuse.
7. **Document the asset** in the inventory and mark it as either approved, deprecated, or pending decommissioning.

Example temporary DNS removal if the subdomain is not needed:
```dns
; Remove or comment out the record until approved
; scottdemo.webgoat. IN A 203.0.113.10
```

Example temporary web-layer restriction:
```nginx
server {
    server_name scottdemo.webgoat;

    allow 192.0.2.0/24;
    deny all;
}
```

**Permanent Remediation**

1. **Establish authoritative asset management** for all subdomains, including business owner, technical owner, environment type, and lifecycle status.
2. **Create and enforce a subdomain approval workflow** so new DNS records cannot be published without security review and documented purpose.
3. **Remove or decommission unused subdomains** by deleting DNS records, disabling hosting, and revoking associated certificates, credentials, and infrastructure resources.
4. **Harden any required host** behind the subdomain by applying least-privilege network access, secure configuration baselines, patch management, and authenticated access controls.
5. **Eliminate sensitive exposure** by ensuring no debug pages, test data, internal tools, directory listings, or verbose error messages are reachable from the public Internet.
6. **Implement continuous external attack surface monitoring** to detect newly published subdomains and validate that they match approved inventories.
7. **Automate DNS and certificate lifecycle management** so retired hosts are fully removed and orphaned records do not persist.
8. **Perform periodic recon-style reviews** against your own domains to identify unexpected subdomains and correct drift quickly.
9. **Add ownership and expiration controls** for demo, staging, or temporary systems, including automatic shutdown dates and review checkpoints.
10. **Update operational procedures** so subdomains are treated as Internet-facing assets and undergo security review before publication.

Example of a controlled DNS and hosting lifecycle process:
```yaml
subdomain_lifecycle:
  request:
    required_fields:
      - business_owner
      - technical_owner
      - purpose
      - environment
      - expiration_date
  approval:
    security_review: required
    dns_admin: required
  retirement:
    steps:
      - disable service
      - remove dns record
      - revoke certificate
      - archive logs
      - verify no traffic
```

Example decommission checklist:
```bash
# 1. Stop the service
sudo systemctl stop scottdemo-web

# 2. Disable startup
sudo systemctl disable scottdemo-web

# 3. Remove DNS record in authoritative zone
# 4. Revoke/expire TLS certificate
# 5. Confirm resolution no longer returns the host
nslookup scottdemo.webgoat
```

---

#### F-011 — Subdomain: leonardtestnew.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-011 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: leonardtestnew.webgoat via rapiddns

**Business Impact**

None; this is passive subdomain discovery only and does not indicate a reachable service or misconfiguration by itself. Exploitation would require the discovered host to expose vulnerable content or services, which is not shown here.

**Analyst Note**

> Informational DNS reconnaissance result from subfinder/rapiddns. The presence of leonardtestnew.webgoat indicates an externally discoverable hostname, but no vulnerability is evidenced beyond asset enumeration.

**Short-term Mitigation**

1. **Validate exposure**: Confirm whether `leonardtestnew.webgoat` is publicly resolvable and whether it points to an active host, application, or test environment.
2. **Restrict access immediately if unintended**: If the subdomain should not be public, remove or disable the DNS record temporarily, or point it to a non-routable/internal address while you assess necessity.
3. **Apply access controls**: If the host must remain online, restrict access via **VPN**, **IP allowlisting**, **basic authentication**, or a **WAF/reverse proxy** until the environment is reviewed.
4. **Banner/page hardening**: If the host is intended only for internal testing, ensure it does not expose sensitive version information, debug pages, or administrative interfaces.
5. **Inventory and ownership check**: Identify the business owner, hosting platform, and purpose of the subdomain to determine whether it is approved and should remain active.
6. **Certificate review**: Verify any TLS certificate issued for the subdomain is expected; revoke or replace any certificate that was created without approval.
7. **Monitoring**: Add temporary monitoring for requests, DNS queries, and access logs to detect unexpected activity against the host.

```bash
# Example: verify current DNS resolution
nslookup leonardtestnew.webgoat

# Example: check HTTP/S exposure
curl -I http://leonardtestnew.webgoat
curl -Ik https://leonardtestnew.webgoat
```

8. **Communicate risk internally**: Inform the application and infrastructure owners that the host is discoverable externally and may be cataloged by attackers, even if it currently has no known vulnerability.

**Permanent Remediation**

1. **Confirm asset legitimacy and lifecycle**: Determine whether `leonardtestnew.webgoat` is a sanctioned production, staging, or lab asset. If it is not required, formally decommission it and remove all associated DNS, hosting, and certificate artifacts.
2. **Remove unnecessary DNS records**: Delete obsolete `A`, `AAAA`, `CNAME`, and related records from authoritative DNS zones and any third-party DNS providers to prevent future discovery and reduce attack surface.

```dns
; Example of a record to remove in zone management tools
leonardtestnew.webgoat.   IN   CNAME   old-host.example.internal.
```

3. **Enforce subdomain governance**: Establish a documented approval workflow for new subdomains, including business justification, owner assignment, expiration date, and environment classification (production vs. non-production).
4. **Implement asset inventory management**: Maintain a centralized inventory of all domains, subdomains, IPs, and certificates. Reconcile DNS records against this inventory on a scheduled basis to identify stale or unauthorized entries.
5. **Segregate non-production environments**: If the host is intended for testing or training, move it behind private network boundaries or require authenticated access through VPN, bastion, or zero-trust access controls.
6. **Harden exposed services**: For any subdomain that must remain public, ensure the underlying service is fully patched, minimally exposed, and protected by least-privilege firewall rules, secure headers, and strong authentication where applicable.
7. **Certificate and TLS hygiene**: Ensure certificates are issued only for approved hosts, rotate certificates as needed, and remove unused SAN entries associated with retired subdomains.
8. **Periodic external reconnaissance checks**: Continuously test your own perimeter using approved passive and active discovery to identify newly exposed or orphaned subdomains before they are found by others.

```bash
# Example: locate DNS records during cleanup/review
subfinder -d webgoat -silent

# Example: compare discovered hosts to approved inventory
comm -23 discovered.txt approved-subdomains.txt
```

9. **Document exception handling**: If the subdomain must remain public for a valid reason, document the acceptable risk, owner, scope, and compensating controls, and review it regularly.

---

#### F-012 — Subdomain: beta.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-012 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: beta.webgoat via rapiddns

**Business Impact**

Not directly exploitable by itself; this is passive subdomain discovery only. Any risk depends on whether beta.webgoat resolves and exposes services, which would require separate probing and enumeration.

**Analyst Note**

> Informational finding from subfinder/radiddns indicating the presence of the beta.webgoat hostname. No vulnerability is demonstrated; treat as attack-surface discovery that may warrant follow-up resolution and service checks.

**Short-term Mitigation**

1. **Validate exposure immediately**: Confirm whether `beta.webgoat` is intended to exist and whether it currently resolves publicly. If it is not meant to be externally reachable, remove or disable the DNS record until a review is completed.
2. **Restrict access at the edge**: If the subdomain must remain available for testing, place it behind **IP allowlisting**, **VPN**, **SSO**, or a **reverse proxy** requiring authentication so only authorized users can reach it.
3. **Apply temporary DNS controls**: Lower the risk of opportunistic discovery by changing the record to a non-public target where appropriate, or point it to a controlled maintenance page if the service is not ready for exposure.
4. **Harden the hosting endpoint**: Ensure the underlying host is patched, service banners are minimized, and default/debug/test content is removed to reduce follow-on enumeration risk.
5. **Monitor access attempts**: Enable or verify logging on DNS, reverse proxy, WAF, and application layers to identify unexpected traffic to `beta.webgoat` and support rapid containment if exposed.
6. **Review certificate and perimeter rules**: Confirm there are no wildcard certificates, firewall rules, or load balancer listeners unintentionally advertising the subdomain or forwarding traffic to an internal environment.

```bash
# Example: verify DNS resolution and current exposure
nslookup beta.webgoat
curl -I https://beta.webgoat
```
7. **Communicate ownership**: Notify the service owner and infrastructure team so the record is tracked as an exposure item rather than ignored as a low-priority informational finding.

**Permanent Remediation**

1. **Inventory and ownership**: Create or update an authoritative inventory of all approved subdomains for `webgoat`, including business owner, environment, purpose, and lifecycle status. Remove any record that is not explicitly approved.
2. **Eliminate unnecessary public DNS records**: Permanently delete obsolete or unapproved DNS entries for `beta.webgoat` from the authoritative zone and any delegated DNS providers.
3. **Implement DNS change control**: Require ticketed approval, peer review, and expiration dates for new subdomain creation. Treat test or beta hostnames as time-bound assets that must be decommissioned when no longer needed.
4. **Separate environments**: Host beta/test services in isolated infrastructure and, where possible, use internal-only DNS zones so non-production assets are not publicly discoverable.
5. **Enforce access controls by design**: If `beta.webgoat` must remain public-facing, protect it with strong authentication, least-privilege network policy, and explicit allowlists for administrative or pre-release access.
6. **Reduce passive discovery surface**: Review what external sources index the subdomain (DNS providers, CT logs, vendor portals, monitoring pages). Remove accidental references and ensure no public documentation exposes non-production hostnames.
7. **Automate continuous asset discovery**: Add recurring scans and alerts for newly observed subdomains so unapproved records are detected quickly and routed to ownership for validation.
8. **Decommission safely**: If the subdomain is no longer needed, follow a formal retirement process: remove application bindings, revoke certificates, delete DNS records, clear load balancer listeners, and confirm it no longer resolves publicly.
9. **Document and verify**: Update architecture diagrams, runbooks, and CMDB entries to reflect the final state. Re-test after changes to confirm the subdomain is either removed or properly protected.

```bash
# Example verification after remediation
nslookup beta.webgoat || true
curl -I https://beta.webgoat
```
10. **Acceptance criteria**: The issue is considered remediated when `beta.webgoat` is either absent from public DNS or is intentionally published with documented ownership and enforced access restrictions, with monitoring in place for future changes.

---

#### F-013 — Subdomain: webdisk.acag.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-013 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: webdisk.acag.webgoat via rapiddns

**Business Impact**

This is only an information disclosure finding. A discovered subdomain is typically easy to enumerate once found, but it is not itself directly exploitable without an actual service or misconfiguration behind the host.

**Analyst Note**

> subfinder/rapiddns enumerated an additional subdomain under webgoat. As reported, this does not indicate a vulnerability by itself; it is useful for attack surface mapping only. No evidence of exposed service, misconfiguration, or sensitive data on the host was provided.

**Short-term Mitigation**

1. **Validate the subdomain’s purpose**: Confirm whether `webdisk.acag.webgoat` is an approved, business-required host or an orphaned entry.
2. **Restrict exposure if not needed**: If the host is not intended for public use, temporarily remove or disable the DNS record to prevent further discovery.
3. **Apply access controls**: If the service must remain online, restrict access via firewall, reverse proxy, VPN, or IP allowlisting until a permanent decision is made.
4. **Disable unnecessary service features**: Remove any publicly reachable directory listings, admin panels, test endpoints, or default pages associated with the host.
5. **Review for misconfiguration**: Check for accidental exposure of internal content, backup directories, credentials, or debug interfaces behind the subdomain.
6. **Monitor for abuse**: Add temporary logging and alerting for requests to this host to detect scanning, enumeration, or unexpected access patterns.
7. **Harden DNS visibility**: Ensure the subdomain is not published in unnecessary external documentation, public code repositories, or automation outputs.
8. **Document ownership**: Assign an owner and ticket for the host so it is either formally approved or decommissioned.

```bash
# Example: identify DNS record source and remove if unnecessary
nslookup webdisk.acag.webgoat
# then update DNS zone or provider to delete the record
```

```nginx
# Example: temporary access restriction at reverse proxy
server {
    server_name webdisk.acag.webgoat;
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;
}
```

**Permanent Remediation**

1. **Establish authoritative subdomain governance**: Create a formal process for requesting, approving, documenting, and decommissioning subdomains so unmanaged records do not persist.
2. **Inventory all DNS assets**: Maintain a complete, regularly reconciled inventory of public DNS zones, subdomains, and their owning teams to prevent orphaned exposures.
3. **Remove unnecessary public records**: Permanently delete any subdomain that does not support a valid business function or that has no associated service lifecycle ownership.
4. **Implement DNS change control**: Require peer review and approval for DNS changes, including creation, modification, and deletion of subdomain records.
5. **Enforce least exposure**: Publish only the minimal set of hostnames required for business operations; keep internal, test, and administrative hosts off public DNS whenever possible.
6. **Standardize service hardening**: For approved hosts, ensure the associated application uses secure defaults, authentication, and network restrictions appropriate to the data exposed.
7. **Decommission stale infrastructure**: If the subdomain points to retired infrastructure, remove the service, clean up certificates, delete associated load balancer entries, and revoke any unused credentials.
8. **Integrate continuous discovery monitoring**: Add recurring external attack surface monitoring to detect newly exposed or resurrected subdomains and alert owners immediately.
9. **Protect against future leaks**: Review CI/CD pipelines, documentation, third-party vendors, and code repositories to ensure subdomains are not inadvertently disclosed.
10. **Verify closure**: After remediation, re-scan external DNS and confirm the subdomain no longer resolves or is intentionally restricted.

```bash
# Example: confirm record removal after cleanup
dig webdisk.acag.webgoat any
# Expected: no answer / NXDOMAIN / no public resolution, depending on DNS design
```

```text
DNS governance checklist:
- Business owner assigned
- Technical owner assigned
- Exposure approved
- Security review completed
- Decommission date defined
- Revalidation scheduled
```

---

#### F-014 — Subdomain: webmail.leonardtestnew.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-014 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: webmail.leonardtestnew.webgoat via rapiddns

**Business Impact**

This is only passive subdomain discovery and does not indicate a reachable service, misconfiguration, or vulnerable application. Exploitation is not applicable until the hostname is resolved and an exposed service is verified.

**Analyst Note**

> Informational asset discovery result from subfinder/rapiddns. The presence of webmail.leonardtestnew.webgoat suggests a DNS record exists, but no proof of HTTP(S), SMTP, or any other service exposure is provided.

**Short-term Mitigation**

1. **Verify ownership and exposure**: Confirm whether `webmail.leonardtestnew.webgoat` is an intended and authorized asset. If it is not required, treat it as an unapproved discovery and document it for asset inventory review.
2. **Check DNS resolution and reachability**: Validate whether the hostname resolves publicly and whether any service is exposed.
```bash
nslookup webmail.leonardtestnew.webgoat
dig webmail.leonardtestnew.webgoat A +short
dig webmail.leonardtestnew.webgoat CNAME +short
```
3. **Reduce immediate exposure**: If the subdomain is not needed, remove or disable the public DNS record(s) temporarily, or point them to a non-routable sink until ownership is confirmed.
```dns
; Example placeholder actions (implementation depends on DNS provider)
; Delete A/AAAA/CNAME record for webmail.leonardtestnew.webgoat
; Or replace with a controlled internal-only target
```
4. **Restrict access if the service exists**: If a webmail service is active, place it behind access controls such as VPN, IP allowlisting, or authentication gateway until a full review is completed.
5. **Audit certificates and virtual host configuration**: Check whether TLS certificates or reverse proxy configurations unintentionally expose the hostname.
6. **Update the asset inventory**: Add the hostname to the asset register as either approved, deprecated, or pending removal so it is tracked during remediation.
7. **Monitor for external access attempts**: Review DNS logs, reverse proxy logs, and web server logs for requests to this hostname to determine whether it is being probed or used.
8. **Communicate with relevant stakeholders**: Notify DNS, infrastructure, and application owners that the subdomain was discovered and requires validation to avoid accidental service exposure.

**Permanent Remediation**

1. **Establish authoritative asset ownership**: Assign a clear owner for `webmail.leonardtestnew.webgoat` and determine whether the subdomain is required for business or lab operations. If it is not required, formally decommission it.
2. **Remove unused DNS records**: Delete all unnecessary public DNS records associated with the hostname, including `A`, `AAAA`, and `CNAME` entries, and verify that no wildcard records or delegated zones continue to expose it.
```bash
dig webmail.leonardtestnew.webgoat ANY +short
```
3. **Harden DNS governance**: Implement change control for DNS creation and modification so that subdomains cannot be published without approval, documentation, and an owner.
4. **Inventory and classify subdomains**: Maintain a continuously updated subdomain inventory with classification tags such as **public**, **internal-only**, **lab**, or **retired**. Reconcile new discoveries against this inventory regularly.
5. **Deploy DNS monitoring and alerting**: Use passive DNS, certificate transparency monitoring, and external attack surface management to detect newly introduced subdomains and unauthorized DNS changes.
6. **Limit exposure of webmail services**: If a webmail portal is legitimately required, host it only on hardened infrastructure and restrict it via VPN, SSO, conditional access, or IP allowlists where possible.
7. **Implement secure reverse proxy controls**: Ensure only intended hostnames are routed by the load balancer or reverse proxy, and reject unknown host headers or unexpected virtual hosts.
```nginx
server {
    listen 443 ssl;
    server_name webmail.leonardtestnew.webgoat;
    # enforce authentication and access restrictions here
}
```
8. **Review TLS and email-related infrastructure**: Confirm that certificates, mail gateways, and webmail front ends do not expose staging, test, or deprecated hostnames in SANs, redirects, or configuration files.
9. **Perform periodic external attack surface assessments**: Schedule recurring subdomain enumeration and validation to catch forgotten assets before they become publicly exposed.
10. **Document decommissioning procedures**: For retired subdomains, remove DNS entries, disable related services, revoke certificates if needed, and confirm the hostname returns NXDOMAIN or a controlled non-public response.
```bash
dig webmail.leonardtestnew.webgoat A
# Expected after removal: no public resolution / NXDOMAIN, depending on DNS design
```

---

#### F-015 — Subdomain: ns2.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-015 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: ns2.webgoat via rapiddns

**Business Impact**

This is not directly exploitable by itself; it is only evidence that a subdomain record exists. Practical impact depends on whether ns2.webgoat resolves to a live service and exposes misconfigured DNS or administrative functionality, which is not shown here.

**Analyst Note**

> Informational subdomain discovery from passive DNS enumeration. The specific host ns2.webgoat appears to be a nameserver-style label, but no service validation, response data, or security weakness is demonstrated, so this should not be treated as a vulnerability on its own.

**Short-term Mitigation**

1. **Validate the subdomain**: Confirm whether `ns2.webgoat` is intentionally published and whether it resolves to an active host.
2. **Restrict exposure if unintended**: If the subdomain is not required, temporarily remove or disable the DNS record to prevent further enumeration and reduce attack surface.
3. **Limit service access**: If `ns2.webgoat` is a live nameserver or administrative endpoint, restrict inbound access to trusted IP ranges only.
4. **Harden DNS management access**: Ensure that only authorized administrators can modify DNS records and related infrastructure.
5. **Monitor for abuse**: Review DNS query logs and server logs for unusual activity targeting `ns2.webgoat`.
6. **Assess for related findings**: Check whether the subdomain is associated with exposed zone transfer, misconfigured DNS recursion, or outdated management interfaces.

Example temporary ACL for a DNS or admin service:
```bash
# Allow only internal/admin networks
iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 53 -j ACCEPT
iptables -A INPUT -p udp -s 10.0.0.0/8 --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j DROP
iptables -A INPUT -p udp --dport 53 -j DROP
```

**Permanent Remediation**

1. **Inventory and ownership**: Maintain an authoritative inventory of all subdomains, their business purpose, and their assigned owners so that every DNS record is justified and reviewed.
2. **Remove unused records**: Permanently delete obsolete or unintended records for `ns2.webgoat` from the DNS zone to prevent continued exposure during recon and reduce attack surface.
3. **Implement DNS change control**: Require peer review and approval for all DNS changes, including creation, modification, and deletion of subdomains.
4. **Harden DNS servers**: If `ns2.webgoat` is intended to be a nameserver, ensure it is configured securely:
   - disable open recursion unless explicitly required;
   - restrict zone transfers to approved secondary servers;
   - patch and update DNS software regularly;
   - separate authoritative DNS from management interfaces.
5. **Protect administrative interfaces**: If the host exposes admin panels or control planes, move them behind VPN, SSO, or IP allowlisting and enforce MFA.
6. **Apply least privilege**: Limit who can administer DNS and server infrastructure, using role-based access control and just-in-time access where possible.
7. **Monitor and alert**: Enable centralized logging for DNS queries, configuration changes, and authentication attempts, with alerts for suspicious activity such as zone transfer attempts or unexpected access.
8. **Validate externally**: After changes, re-scan the domain to confirm `ns2.webgoat` no longer appears if removed, or verify that any remaining exposure is intentionally limited and secured.

Example BIND hardening snippet:
```conf
options {
    recursion no;
    allow-transfer { 10.0.0.2; 10.0.0.3; };
};

controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; };
};
```

Example operational verification:
```bash
# Confirm the record is gone or intentional
nslookup ns2.webgoat
# Check for unauthorized zone transfers
nmap --script dns-zone-transfer -p 53 ns2.webgoat
```

---

#### F-016 — Subdomain: cpanel.scottdemo.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-016 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: cpanel.scottdemo.webgoat via rapiddns

**Business Impact**

Low; this is passive subdomain discovery with no direct vulnerability demonstrated. Exploitation would require the discovered host to resolve and expose a service with a weakness, which is not established by this finding alone.

**Analyst Note**

> Informational asset discovery only. The host cpanel.scottdemo.webgoat appears to be a subdomain enumerated via passive DNS (rapiddns); this does not by itself indicate misconfiguration, exposure, or a security flaw.

**Short-term Mitigation**

1. **Verify exposure**: Confirm whether `cpanel.scottdemo.webgoat` resolves publicly and whether any services are reachable from the internet.
2. **Restrict access immediately**: If the host is not intended for public use, place it behind IP allowlisting, VPN, or a firewall rule set that blocks external access.
3. **Disable unused service exposure**: If the subdomain is unused or obsolete, remove or pause the DNS record to prevent further discovery and connection attempts.
4. **Harden the service if it must remain public**: Ensure the administrative interface is protected with strong authentication, MFA, and rate limiting; require HTTPS only.
5. **Monitor for abuse**: Review logs for unsolicited traffic, brute-force attempts, or scanning activity against the host and related infrastructure.
6. **Temporarily deindex and reduce discoverability**: If applicable, add `X-Robots-Tag` headers and ensure no public links reference the hostname, though this does not replace access control.
7. **Validate DNS hygiene**: Check for stale, orphaned, or wildcard DNS entries that may expose legacy services unintentionally.

```bash
# Example: confirm resolution and basic exposure
nslookup cpanel.scottdemo.webgoat
curl -Ik https://cpanel.scottdemo.webgoat
```

```text
# Example firewall approach
Allow: trusted admin IP ranges only
Deny: all other source addresses
```


**Permanent Remediation**

1. **Inventory ownership and purpose**: Determine who owns `cpanel.scottdemo.webgoat`, what service it is meant to provide, and whether it is still required.
2. **Remove unnecessary subdomains**: If the hostname is obsolete, delete the DNS record and decommission any associated host or virtual service to eliminate attack surface.
3. **Implement least-exposure DNS design**: Publish only the subdomains that are needed, avoid broad wildcard records where possible, and maintain an authoritative DNS inventory with change control.
4. **Place administrative interfaces behind controlled access**: Administrative portals such as cPanel should not be exposed broadly to the internet unless absolutely necessary. Use a VPN, reverse proxy with strong auth, or network ACLs to limit access.
5. **Enforce secure service configuration**: Require TLS, disable legacy protocols and weak ciphers, and ensure the administrative portal is configured according to vendor hardening guidance.
6. **Protect with identity controls**: Enable MFA for all administrative accounts, strong password policy, account lockout, and role-based access control.
7. **Introduce continuous monitoring**: Add DNS change monitoring, host discovery monitoring, and alerting for newly observed subdomains so unintended exposure is detected quickly.
8. **Establish decommissioning procedures**: When services are retired, remove DNS entries, disable certificates, revoke credentials, and delete associated infrastructure artifacts to prevent stale exposure.
9. **Review certificates and hostnames**: Ensure certificates, virtual host mappings, and backend services are aligned so that dormant hostnames do not continue to respond unexpectedly.
10. **Validate after changes**: Re-scan external DNS and web exposure to confirm the hostname is no longer publicly reachable or is properly constrained.

```bash
# Example: remove an obsolete DNS record (provider-specific syntax varies)
# After deletion, confirm no resolution remains
nslookup cpanel.scottdemo.webgoat
```

```nginx
# Example: restrict access to an admin portal at the reverse proxy
location / {
    allow 203.0.113.10;
    allow 198.51.100.0/24;
    deny all;
    proxy_pass https://backend_admin;
}
```

```apache
# Example: require authenticated access (illustrative)
<Directory "/var/www/admin">
    Require ip 203.0.113.10 198.51.100.0/24
</Directory>
```


---

#### F-017 — Subdomain: donna.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-017 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: donna.webgoat via rapiddns

**Business Impact**

Low. This is passive subdomain enumeration with no direct attack surface demonstrated; exploitation would require resolving the host and finding an actual exposed service or misconfiguration.

**Analyst Note**

> The finding only confirms discovery of the subdomain via DNS intelligence sources. By itself it does not indicate a vulnerability, just potential additional attack surface that should be validated separately.

**Short-term Mitigation**

1. **Validate exposure immediately**: Resolve `donna.webgoat` from trusted internal and external vantage points and confirm whether it points to a live service, stale record, parked host, or sinkhole.
2. **Restrict access if a service is active**: If the subdomain resolves to an operational system, place it behind **temporary access controls** such as IP allowlisting, VPN-only access, or an upstream reverse proxy with authentication.
3. **Disable unnecessary services**: Shut down any service bound to the host that is not required for business purposes, especially if it is a test, staging, or forgotten environment.
4. **Remove or quarantine sensitive content**: If the host exposes admin consoles, debug pages, backups, or default content, remove them immediately or isolate the host from public access until hardened.
5. **Verify DNS records**: Review the DNS entry for `donna.webgoat` and remove any record that is no longer needed. If the host must remain reserved, point it to a controlled landing page or sinkhole that does not expose infrastructure details.
6. **Check for linked assets**: Inspect web server logs, certificate transparency logs, and content references to determine whether other related subdomains or services are exposed and should also be protected.
7. **Monitor for abuse**: Add temporary monitoring for requests to the hostname and alert on unexpected traffic, scanning, or authentication failures.

Example containment checks:
```bash
nslookup donna.webgoat
curl -I https://donna.webgoat
```

Example temporary access control concept:
```nginx
location / {
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;
}
```

**Permanent Remediation**

1. **Perform a subdomain inventory**: Establish an authoritative inventory of all approved DNS names for the environment, including ownership, purpose, hosting location, and lifecycle status.
2. **Classify `donna.webgoat`**: Determine whether the subdomain is **active, deprecated, or unauthorized**. Assign an owner and confirm whether it is intended to be publicly reachable.
3. **Remove unused DNS entries**: Permanently delete stale or abandoned records from the DNS zone file and from any third-party DNS providers or automation pipelines that may re-create them.
4. **Harden any required service**: If the host must remain public, apply standard hardening: patch the OS and application, remove default accounts, enforce strong authentication, use TLS, disable directory listing, and restrict administrative interfaces.
5. **Implement least-privilege publishing**: Only publish DNS records for systems with a defined business need. Use separate naming conventions for internal, staging, and production hosts to avoid accidental exposure.
6. **Protect future DNS changes**: Put DNS updates under change control with peer review, ticketing, and expiry dates for temporary records so they are automatically revisited and removed.
7. **Add continuous discovery and monitoring**: Integrate passive and active subdomain discovery into recurring security reviews so new or unexpected hostnames are detected early.
8. **Document ownership and decommissioning**: Maintain a formal decommission process that includes DNS removal, certificate revocation where applicable, log retention, and validation that no services remain reachable.
9. **Validate external exposure after remediation**: Re-scan the domain namespace from an external perspective to confirm that `donna.webgoat` is no longer exposed or is only reachable through approved controls.

Example DNS zone cleanup workflow:
```bash
# Review zone entries
named-checkzone webgoat.example /etc/bind/zones/db.webgoat

# After approval, remove stale record from the zone file and reload
rndc reload webgoat.example
```

Example lifecycle control policy:
```yaml
subdomain_management:
  owner_required: true
  purpose_required: true
  expiry_required_for_temporary_records: true
  quarterly_review: true
  remove_unused_records: true
```

---

#### F-018 — Subdomain: 220-khan.webgoat

| Field | Detail |
|:------|--------|
| **Identifier** | F-018 |
| **Severity** | ⚪ INFO |
| **Status** | Open |
| **Affected System** | webgoat |
| **Detected By** | subfinder |
| **Confidence** | High |
| **CWE** | — |
| **CVEs** | — |
| **Cluster** | cluster-2 |

**Description**

Discovered subdomain: 220-khan.webgoat via rapiddns

**Business Impact**

This is a passive discovery finding; by itself a subdomain record is not directly exploitable. Any risk depends on whether the host resolves, is publicly reachable, and exposes vulnerable services or misconfigurations.

**Analyst Note**

> Subfinder has enumerated an additional subdomain under webgoat from public DNS/OSINT sources. This is informational inventory data rather than a security vulnerability, but it can expand the attack surface if the host is active and unprotected.

**Short-term Mitigation**

1. **Verify exposure**: Confirm whether `220-khan.webgoat` actually resolves in DNS and whether it is reachable from untrusted networks. If it is not required, temporarily **disable the DNS record** or point it to a non-routable/internal address.
2. **Restrict access immediately**: If the host must remain online, apply **network controls** to limit access to trusted IP ranges only.
   ```bash
   # Example: allow only corporate/VPN source addresses
   ufw default deny incoming
   ufw allow from <trusted_cidr> to any port 80,443 proto tcp
   ufw enable
   ```
3. **Reduce service exposure**: Shut down or disable any unnecessary services on the host until a full review is complete.
   ```bash
   # Example service review
   ss -tulpn
   systemctl list-units --type=service --state=running
   ```
4. **Harden DNS visibility**: If the subdomain is intended for internal use, move it to a **private DNS zone** or split-horizon DNS so it is not publicly resolvable.
5. **Add temporary monitoring**: Enable logging and alerting for requests to the host to detect unexpected access or scanning activity.
6. **Validate TLS and app behavior**: If the subdomain serves web content, ensure it is not exposing admin panels, debug endpoints, or default pages while investigation is ongoing.
7. **Document ownership**: Identify the business owner, system owner, and intended purpose of the subdomain to determine whether it should exist at all.

**Permanent Remediation**

1. **Establish asset ownership and lifecycle management**: Create an authoritative inventory of approved subdomains, including owner, purpose, environment, and retirement date. Remove orphaned or unused entries from DNS and infrastructure records.
2. **Implement DNS governance**: Require change control for all new subdomain creation and deletion requests. Enforce review/approval before adding public records.
   ```text
   Change request fields:
   - Subdomain name
   - Business owner
   - Technical owner
   - Purpose
   - Expected IP/target
   - Public or internal-only
   - Expiration/review date
   ```
3. **Use private DNS for internal services**: Any host not meant for public access should be migrated to **internal DNS** only. For externally needed names, ensure only the minimum necessary records are published.
4. **Apply least-exposure architecture**: Place public-facing applications behind a reverse proxy, WAF, or load balancer and restrict direct origin access with firewall rules or security groups.
   ```bash
   # Example cloud security group principle
   # Allow 80/443 only from load balancer/WAF IPs
   # Deny all other inbound access to origin
   ```
5. **Standardize service hardening**: Build and enforce hardened baselines for web servers and application hosts, including disabled directory listing, removed default content, patched components, and secure headers.
   ```nginx
   server_tokens off;
   add_header X-Content-Type-Options nosniff always;
   add_header X-Frame-Options DENY always;
   add_header Content-Security-Policy "default-src 'self'" always;
   ```
6. **Continuously monitor DNS and internet exposure**: Integrate subdomain discovery into routine attack surface management so newly published or forgotten hosts are identified quickly and reviewed.
7. **Retire unused subdomains**: When a subdomain is no longer needed, remove its DNS record, shut down the service, revoke certificates, and clear any associated infrastructure to prevent stale exposure.
8. **Perform periodic validation**: Schedule recurring checks to confirm that every public subdomain is intentional, reachable only as designed, and free of unnecessary services or misconfigurations.
9. **Add detection and alerting**: Forward DNS changes, web access logs, and firewall events to the SIEM so unexpected public exposure is detected and investigated promptly.

---

## Appendix A — Scan Errors

The following tools encountered errors during the assessment.
These are tool execution failures, not security findings.

| Target | Tool | Error |
|--------|------|-------|
| `dvwa` | `smbmap` | Exit code 2: usage: smbmap [-h] (-H HOST \| --host-file FILE) [-u USERNAME] [-p PASSWORD \|               --prompt] [-k] [--no-pass] [--dc-ip IP or Host] [-s SHARE]               [-d DOMAIN] [-P PORT] [ |
| `juice-shop` | `smbmap` | Exit code 2: usage: smbmap [-h] (-H HOST \| --host-file FILE) [-u USERNAME] [-p PASSWORD \|               --prompt] [-k] [--no-pass] [--dc-ip IP or Host] [-s SHARE]               [-d DOMAIN] [-P PORT] [ |
| `webgoat` | `smbmap` | Exit code 2: usage: smbmap [-h] (-H HOST \| --host-file FILE) [-u USERNAME] [-p PASSWORD \|               --prompt] [-k] [--no-pass] [--dc-ip IP or Host] [-s SHARE]               [-d DOMAIN] [-P PORT] [ |

---


---

*Report generated by vuln-scanner · 2026-07-16 22:57:08 UTC*
