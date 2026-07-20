# Scanning Tools

| Marker | Meaning |
|--------|---------|
| `[x]`  | Implemented |
| `[ ]`  | Not yet integrated|
| `[~]`  | Out of scope — see criteria below |

## Out-of-scope criteria

A tool is marked `[~]` when it falls into one or more of the following categories:

- **GUI / interactive only** — no headless CLI mode that can be invoked via subprocess and captured (e.g. Maltego, Ghidra, Caido, Cutter, OWASP Threat Dragon)
- **Framework / library** — requires custom scripting to produce output; not a standalone scanner (e.g. Frida, pwntools, PyTM, PyRIT, LibAFL, Boofuzz)
- **Runtime daemon** — runs continuously as a system service; not a one-shot scan (e.g. Falco)
- **Requires an active session or instrumented binary** — cannot be pointed at an arbitrary target (e.g. Pacu, AFL++, Jazzer, Radamsa)
- **External SaaS / API-only** — depends on a paid external service or cloud account to function (e.g. Shodan CLI, Censys CLI, FOSSA CLI, Cartography → Neo4j)
- **Graph / visualisation tool** — populates a database or produces diagrams, not scan findings (e.g. Cartography, Maltego)
- **Pre-commit hook** — designed to gate commits, not to scan an arbitrary target on demand
- **Commercial / hosted platform** — self-hosted edition either unavailable or restricted (already covered by the original `[~]` meaning)
- **Pipeline utility** — transforms or deduplicates stdin/stdout; produces no vulnerability findings (e.g. anew, unfurl)

---

## Web Application Scanning

- [x] Acunetix *(self-hosted edition — REST API, requires VS_ACUNETIX_URL + VS_ACUNETIX_API_KEY)*
- [x] Arachni
- [x] Drheader *(HTTP security header analysis)*
- [x] Nikto
- [x] Wapiti
- [x] WPScan *(WordPress-specific)*
- [x] ZAP (OWASP Zed Attack Proxy)
- [x] SQLMap *(SQL injection detection and exploitation)*
- [x] ffuf *(fast web fuzzer — directory/parameter discovery)*
- [x] Feroxbuster *(recursive content discovery)*
- [x] Gobuster *(directory, DNS, and vhost brute-forcing)*
- [x] Wfuzz *(web fuzzer)*
- [x] Dalfox *(XSS parameter analysis)*
- [x] Commix *(command injection detection)*
- [x] WhatWeb *(web technology fingerprinting)*
- [x] WafW00f *(WAF detection and fingerprinting)*
- [x] Katana *(fast web crawler — ProjectDiscovery)*
- [x] Httpx *(HTTP toolkit: probing, status, tech detection)*
- [x] Arjun *(HTTP parameter discovery)*
- [x] CORScanner *(CORS misconfiguration detection)*
- [x] Hakrawler *(web crawler for endpoint discovery)*
- [x] XSStrike *(advanced XSS scanner with crawler and fuzzer)*
- [x] NoSQLMap *(NoSQL injection detection and exploitation)*
- [x] GraphQL Cop *(GraphQL security audit — 15+ checks)*
- [x] ParamSpider *(parameter mining from web archives — no interaction with target)*
- [x] gau *(gather all known URLs — Wayback Machine, CommonCrawl, AlienVault OTX)*
- [x] JSluice *(URL, path, and secret extraction from JavaScript files — Trufflesecurity)*
- [x] dirsearch *(web path discovery — Python, wordlist-based)*
- [x] kxss *(finds reflected XSS parameters in HTTP responses)*
- [x] CRLFsuite *(CRLF injection vulnerability scanner)*
- [x] crlfuzz *(fast CRLF injection scanner — Go)*
- [x] nomore403 *(advanced 403/40x restriction bypass tool)*
- [x] SSRFmap *(automatic SSRF fuzzer and exploitation tool)*
- [~] Gopherus *(payload generator — produces gopher:// URIs for manual use, no scan findings)*
- [ ] dotdotpwn *(directory traversal fuzzer — modular, supports many protocols)*
- [x] jwt_tool *(JWT security testing toolkit — decode, tamper, crack)*
- [x] h2csmuggler *(HTTP/2 cleartext request smuggling scanner)*
- [x] Oralyzer *(open redirect analyzer)*
- [x] tplmap *(server-side template injection detection and exploitation)*
- [x] SSTImap *(SSTI detection with interactive exploitation interface)*
- [x] Corsy *(CORS misconfiguration scanner)*
- [x] ghauri *(advanced cross-platform SQL injection detection tool)*
- [x] XSRFProbe *(CSRF audit and exploitation tool)*
- [~] mitmproxy *(TLS-capable interactive intercepting proxy — no standalone one-shot scan mode)*
- [~] proxify *(HTTP/HTTPS traffic capture proxy — pipeline tool, not a scanner)*
- [x] joomscan *(OWASP Joomla vulnerability scanner)*
- [x] CMSmap *(open-source multi-CMS security scanner — WordPress, Joomla, Drupal)*
- [x] aemhacker *(Adobe Experience Manager vulnerability scanner)*
- [~] RouterSploit *(exploitation framework for routers — interactive session required)*
- [x] WhatWaf *(detect and bypass web application firewalls and protection systems)*
- [x] Jaeles *(Swiss Army knife for automated web application testing — Go, rule-based)*
- [x] BlackWidow *(Python web application scanner for OSINT and OWASP vulnerability discovery)*
- [x] JSParser *(parse relative URLs from JavaScript files using Tornado and JSBeautifier)*
- [x] Parameth *(brute-discover hidden GET and POST parameters)*
- [~] NucleiFuzzer *(thin wrapper around Nuclei + ParamSpider — not a standalone scanner)*
- [~] Caido *(GUI-based proxy — no headless scan mode that produces parseable findings)*
- [~] AppCheck Web Application Scanner
- [~] AppSpider *(Rapid7)*
- [~] Burp Suite *(XML, API, GraphQL, DAST, Dastardly — Community edition limited)*
- [~] Crashtest Security
- [~] HCL AppScan / ASOC SAST
- [~] Immuniweb
- [~] Invicti (Netsparker)
- [~] Microfocus WebInspect
- [~] Mozilla Observatory *(online service)*
- [~] Outpost24
- [~] Rapplex
- [~] SkF *(OWASP training platform)*
- [~] Solar AppScreener
- [~] StackHawk
- [~] Trustwave

## Network & Infrastructure Scanning

- [x] Nmap
- [x] SSH Audit
- [x] Amass *(subdomain enumeration)*
- [x] OpenVAS *(GVM socket integration — requires running GVM daemon)*
- [x] Masscan *(ultra-fast port scanner)*
- [x] RustScan *(fast port scanner, feeds into nmap)*
- [x] Subfinder *(passive/active subdomain enumeration)*
- [x] Dnsx *(multi-purpose DNS toolkit)*
- [x] DNSRecon *(DNS enumeration and zone transfer)*
- [x] Enum4linux-ng *(SMB/Windows/Samba enumeration)*
- [x] SMBMap *(SMB share enumeration and access check)*
- [x] CrackMapExec *(Windows/Active Directory assessment)*
- [x] Hydra *(brute-force login: SSH, FTP, HTTP, SMB, ...)*
- [x] Medusa *(parallel brute-force — complement to Hydra)*
- [x] Netdiscover *(ARP-based network host discovery)*
- [x] theHarvester *(OSINT — emails, subdomains, and hosts from public sources)*
- [x] Fierce *(aggressive DNS enumeration, brute-force, and zone walking)*
- [x] Naabu *(fast port scanner — ProjectDiscovery, pairs well with Nuclei)*
- [x] findomain *(fast cross-platform subdomain enumerator with certificate transparency)*
- [x] massdns *(high-performance passive DNS resolver for bulk subdomain recon)*
- [x] shuffledns *(massdns wrapper with active bruteforce and wildcard filtering)*
- [x] puredns *(fast, accurate DNS resolver with reliable wildcard detection)*
- [x] bbot *(recursive internet scanner with 100+ modules — subdomain, port, web)*
- [x] assetfinder *(find related domains and subdomains from passive sources)*
- [x] VHostScan *(virtual host scanner with reverse lookup and wordlist support)*
- [x] subdominator *(fast subdomain enumeration aggregating 50+ passive sources)*
- [x] zmap *(stateless large-scale internet-wide port/network scanner)*
- [x] alterx *(fast, customizable subdomain wordlist generator — ProjectDiscovery)*
- [x] gotator *(DNS wordlist generator through permutations and mutations)*
- [x] ripgen *(high-performance domain permutation generator — Rust)*
- [x] dnsgen *(powerful DNS name permutation and mutation tool)*
- [x] gauplus *(extended URL gathering from Wayback, CommonCrawl, OTX with proxy support)*
- [x] haktrails *(SecurityTrails API client for subdomain and DNS history recon)*
- [x] csprecon *(discover new domains via Content Security Policy analysis)*
- [x] github-subdomains *(find subdomains via GitHub code search)*
- [x] chaos-client *(Go client for ProjectDiscovery Chaos DNS API — passive subdomain recon)*
- [x] Knockpy *(subdomain enumeration using dictionary attack and DNS queries)*
- [~] Sudomy *(bash wrapper orchestrating 20+ external tools — not a standalone scanner)*
- [x] httprobe *(take a list of domains and probe for working HTTP/HTTPS servers)*
- [~] Recon-ng *(interactive framework — no subprocess-friendly CLI mode; requires module scripting)*
- [~] Shodan CLI *(queries external SaaS — requires paid API key, no local execution)*
- [~] Nexpose *(Rapid7)*
- [~] Qualys *(Infrascan, VMDR, WebApp, Hacker Guardian)*
- [~] Tenable / Nessus
- [~] Cycognito
- [~] Wazuh *(SIEM platform)*

## SSL/TLS

- [x] SSLyze
- [x] testssl.sh
- [x] SSLScan *(fast SSL/TLS scanner)*
- [x] Humble *(HTTP headers + SSL/TLS analysis)*
- [x] TLS-Attacker *(TLS protocol-level attack testing)*
- [~] SSL Labs *(online service)*
- [x] tlsx *(fast TLS grabber and certificate analyser — ProjectDiscovery)*

## Container & Kubernetes Security

- [x] Trivy *(image, filesystem, repo vuln + misconfiguration)*
- [x] Grype *(Anchore — container/package SCA)*
- [x] Syft *(SBOM generation — pairs with Grype)*
- [x] Hadolint *(Dockerfile linter)*
- [x] Dockle *(container image security linting)*
- [x] Docker Bench Security *(CIS Docker benchmark)*
- [x] Kubescape *(K8s cluster security posture — NSA/MITRE)*
- [x] Kubeaudit *(K8s RBAC and security audit)*
- [x] Kube-bench *(CIS K8s benchmark)*
- [x] Kube-hunter *(K8s penetration testing)*
- [x] Kube-score *(K8s object static analysis)*
- [x] Kube-linter *(K8s YAML linting)*
- [x] Popeye *(K8s live cluster resource sanitizer)*
- [~] Falco *(runtime monitoring daemon — not a one-shot CLI scanner; runs continuously as a system service)*
- [x] Dive *(Docker image layer analyser — finds wasted space and secrets left in layers)*
- [x] Terrascan *(see IaC / Cloud Security — also covers K8s/Helm manifests)*
- [~] Anchore Enterprise
- [~] Aqua
- [~] Clair *(requires running registry integration)*
- [~] Harbor Vulnerability *(registry platform)*
- [~] Neuvector / NeuVector Compliance
- [~] Sysdig
- [~] Trivy Operator *(K8s operator — cluster deployment, not a CLI scan)*
- [~] Twistlock / Prisma Cloud
- [~] Zora *(managed K8s SaaS)*

## `SAST (Static Analysis)`

- [x] Semgrep *(multi-language)*
- [x] Bandit *(Python)*
- [x] GoSec *(Go)*
- [x] Nuclei *(template-based — web + SAST patterns)*
- [x] CodeQL *(GitHub semantic code analysis — runs locally via CLI)*
- [x] Brakeman *(Ruby on Rails)*
- [x] Bearer CLI *(multi-language with data-flow analysis)*
- [x] Horusec *(multi-language: Go, Java, Python, Ruby, JS, C#)*
- [x] SpotBugs *(Java bytecode analysis)*
- [x] PMD *(Java, Apex, PLSQL, XML, JS)*
- [x] Infer *(Facebook — Java, C, C++, Objective-C)*
- [x] Flawfinder *(C/C++ security scanner)*
- [x] Cppcheck *(C/C++ static analysis)*
- [x] DevSkim *(multi-language security linter — Microsoft)*
- [x] ESLint *(JavaScript/TypeScript — with security plugins)*
- [x] Psalm *(PHP static analysis with security checks)*
- [x] ProgPilot *(PHP SAST)*
- [x] RuboCop *(Ruby — with security cops)*
- [x] CodeChecker *(C/C++ — wraps Clang Static Analyzer)*
- [x] DawnScanner *(Ruby)*
- [x] Joern *(code property graph — multi-language semantic vulnerability analysis)*
- [x] Insider *(SAST for mobile and web: Swift, Kotlin, Java, JS, C#)*
- [x] weggli *(fast C/C++ semantic search — finds vulnerability patterns)*
- [~] Checkmarx (One, CxFlow, OSA)
- [~] Contrast
- [~] Coverity
- [~] Fortify
- [~] GitHub SAST *(CI/CD integration)*
- [~] GitLab SAST *(CI/CD integration)*
- [~] HuskyCI *(git hook CI integration)*
- [~] IBM AppScan
- [~] Kiuwan / Kiuwan SCA
- [~] PWN SAST
- [~] Semgrep Pro
- [~] SonarQube / SonarQube API *(self-hosted server required)*
- [~] Veracode / Veracode SCA
- [~] Xanitizer

## SCA / Dependency Scanning

- [x] Dependency Check *(OWASP — Java, Node, Python, Ruby, .NET)*
- [x] pip-audit *(Python)*
- [x] OSV Scanner *(Google — multi-language, uses OSV database)*
- [x] Xeol *(end-of-life component detection)*
- [x] Retire.js *(JavaScript library vulnerability detection)*
- [x] npm audit *(Node.js — built into npm)*
- [x] Yarn audit *(Node.js — built into yarn)*
- [x] Bundler-audit *(Ruby gems)*
- [x] cargo-audit *(Rust crates)*
- [x] Govulncheck *(Go modules — official Go toolchain)*
- [x] Nancy *(Go — Sonatype OSS Index)*
- [x] CycloneDX CLI *(SBOM generation and analysis)*
- [x] License Finder *(OSS license compliance — detects GPL/AGPL/etc. in dependencies)*
- [~] FOSSA CLI *(requires FOSSA SaaS account and token — not locally self-contained)*
- [~] Dependency Track *(server platform)*
- [~] GitLab Dependency Scan *(CI/CD integration)*
- [~] Mend (WhiteSource)
- [~] Meterian
- [~] NSP *(deprecated — merged into npm audit)*
- [~] ORT *(complex pipeline orchestration tool)*
- [~] OSS Index *(Sonatype API)*
- [~] Snyk / Snyk Code / Snyk Issue API
- [~] Sonatype Nexus IQ

## Secret Scanning

- [x] Gitleaks
- [x] TruffleHog *(deep git history + verified secrets)*
- [x] detect-secrets *(Yelp — baseline + pre-commit scanning)*
- [x] NoseyParker *(fast Rust-based secret scanner)*
- [x] Whispers *(YAML, JSON, config file secret scanner)*
- [x] Rusty Hog *(Rust — git, S3, Jira, Confluence)*
- [~] Talisman *(pre-commit hook for outgoing secret detection — not a one-shot scanner)*
- [x] SecretFinder *(JavaScript file secret scanner — works on live HTTP URLs)*
- [x] Gitrob *(GitHub organisation recon and secret hunting)*
- [~] git-secrets *(pre-commit credential pattern detection — hook-based, not a standalone scanner)*
- [x] GitTools *(exploit exposed .git directories — dumper, finder, extractor)*
- [x] git-dumper *(dump a git repository from a misconfigured web server)*
- [x] gitjacker *(leak git repositories from misconfigured websites)*
- [x] Gato *(GitHub Actions self-hosted runner enumeration and exploitation)*
- [x] zizmor *(static analysis for GitHub Actions workflow files)*
- [~] shhgit *(monitors public repos in real-time — not a local target scanner)*
- [~] CredScan *(Microsoft — Azure DevOps only)*
- [~] GGShield *(GitGuardian SaaS)*
- [~] GitHub Secrets Detection *(GitHub Actions only)*
- [~] GitLab Secret Detection *(GitLab CI only)*
- [~] Legitify *(GitHub/GitLab config posture — API-based)*
- [~] n0s1 *(Jira/Confluence/Slack scanning — SaaS)*

## IaC / Cloud Security

- [x] Checkov *(Terraform, K8s, Docker, ARM, CloudFormation)*
- [x] tfsec *(Terraform-specific — fast)*
- [x] KICS *(Checkmarx open-source — Terraform, K8s, Docker, Ansible, CF)*
- [x] Terrascan *(Terraform, K8s, Helm, Kustomize, ARM)*
- [x] Regula *(Terraform, CloudFormation — OPA-based)*
- [x] cfn-nag *(AWS CloudFormation linting)*
- [x] Prowler *(AWS/GCP/Azure security posture — open source CLI)*
- [x] ScoutSuite *(multi-cloud audit: AWS, Azure, GCP, Alibaba)*
- [x] Cloudsploit *(open-source cloud security scanner)*
- [x] Threagile *(threat modeling as code)*
- [~] Pacu *(interactive exploitation framework — requires active AWS session; not a passive scanner)*
- [x] Cloudfox *(AWS/Azure attack surface discovery for pentesting)*
- [x] ROADrecon *(Azure AD and Entra ID reconnaissance)*
- [x] S3Scanner *(scan for open and misconfigured AWS S3 buckets)*
- [x] AWSBucketDump *(enumerate S3 buckets for sensitive files and interesting content)*
- [x] CloudScraper *(enumerate cloud storage resources across AWS, Azure, GCP)*
- [~] Cartography *(populates a Neo4j graph database — not a CLI scanner with findings output)*
- [~] AWS Inspector v2 *(AWS service)*
- [~] AWS Security Hub / ASFF *(AWS service)*
- [~] Azure Security Center *(Azure service)*
- [~] Cloudflare Insights *(Cloudflare service)*
- [~] DSOP *(DoD platform)*
- [~] KrakenD Audit *(KrakenD API gateway specific)*
- [~] Orca Security
- [~] Wiz / WizCLI

## System / Host Security

- [x] Lynis *(system security audit: Linux/macOS/Unix)*
- [x] OpenSCAP *(SCAP compliance scanner and hardening)*
- [x] ClamAV *(malware and virus scanning)*
- [x] YARA *(malware pattern matching)*
- [x] rkhunter *(rootkit, backdoor, and local exploit detection)*
- [x] chkrootkit *(rootkit detection)*
- [x] Vuls *(agentless vulnerability scanner for Linux/FreeBSD — CVE-based)*
- [x] Wappalyzer CLI *(technology fingerprinting from HTTP responses)*

## Mobile Application Security

- [x] MobSF *(Mobile Security Framework — Android/iOS static + dynamic)*
- [x] AndroBugs *(Android app vulnerability scanner)*
- [x] QARK *(Android static analysis)*
- [x] APKiD *(Android APK packer/protector identification)*
- [x] APKLeaks *(scan APK files for URIs, endpoints, and secrets)*
- [x] Androwarn *(static code analyzer for Android — detects malicious behavior patterns)*
- [x] Quark-Engine *(Android malware scoring system based on obfuscation-tolerant analysis)*
- [x] MVT *(Mobile Verification Toolkit — forensic tool for detecting iOS/Android spyware)*
- [~] Drozer *(interactive Android security framework — requires device agent; no one-shot scan mode)*
- [~] apktool *(decompiler/rebuilder — not a vulnerability scanner; produces no findings)*
- [~] objection *(interactive runtime exploration via Frida — no standalone scan mode)*
- [~] Frida *(dynamic instrumentation framework — requires custom scripts; not a scanner)*
- [~] Jadx *(Dex-to-Java decompiler — produces source code, not vulnerability findings)*
- [~] Androguard *(reverse engineering library/framework — no standalone scan mode)*
- [~] House *(Frida-based GUI runtime analysis — no standalone scan mode)*
- [~] apk-mitm *(patches APKs for HTTPS inspection — not a vulnerability scanner)*

## API Security Testing

- [~] InQL *(primarily a Burp Suite extension — standalone CLI mode is very limited)*
- [x] Cherrybomb *(OpenAPI/Swagger spec security linter — detects broken object-level auth etc.)*
- [x] kiterunner *(API route content discovery — assetnote, wordlist-based)*
- [x] APIFuzzer *(REST API fuzzer driven from OpenAPI/Swagger spec)*
- [x] RESTler *(Microsoft automated stateful REST API fuzzer)*
- [~] 42Crunch API Security Audit *(SaaS OpenAPI security analysis)*
- [~] Traceable AI *(API threat detection — SaaS)*

## OSINT / Reconnaissance

- [x] SpiderFoot *(automated OSINT framework — 200+ modules, self-hostable CLI)*
- [x] Photon *(fast OSINT web crawler — extracts URLs, emails, keys, files)*
- [x] ReconFTW *(automated full-scope reconnaissance framework combining 35+ tools)*
- [x] waybackurls *(fetch all known URLs for a domain from the Wayback Machine)*
- [x] waymore *(extended Wayback Machine URL discovery with extended filters)*
- [x] xnLinkFinder *(endpoint and parameter discovery from responses and JavaScript)*
- [x] hakip2host *(resolve IP ranges to associated domain names via reverse DNS)*
- [x] WitnessMe *(web inventory tool — screenshots via Pyppeteer, identifies default credentials)*
- [~] anew *(append new unique lines from stdin to a file — pipeline deduplication utility, not a scanner)*
- [~] unfurl *(extract URL components from stdin — pipeline transformation utility, not a scanner)*
- [~] theHarvester *(see Network & Infrastructure — already listed there)*
- [~] Censys CLI *(queries external SaaS — requires paid API key)*
- [~] Maltego CE *(GUI application — no CLI scan mode)*
- [~] Recon-ng *(see Network & Infrastructure — interactive framework)*
- [~] Shodan *(requires API key for deep results)*
- [~] FOFA *(Chinese internet asset search — API-based)*
- [~] ZoomEye *(Cyberspace search engine — API-based)*

## Subdomain Takeover

- [x] subjack *(subdomain takeover detection tool written in Go)*
- [x] SubOver *(fast, concurrent subdomain takeover scanner)*
- [x] dnsReaper *(subdomain takeover detection — 50+ fingerprints)*
- [x] subzy *(subdomain takeover tool based on fingerprint matching)*
- [x] autoSubTakeover *(automated CNAME-based subdomain takeover checker)*
- [x] tko-subs *(detect and takeover subdomains with dead DNS records)*
- [x] second-order *(second-order subdomain takeover scanner)*

## Fuzzing

- [~] AFL++ *(requires source instrumentation or binary lifting — not a target scanner)*
- [~] Boofuzz *(requires writing Python protocol scripts — not invocable against an arbitrary target)*
- [~] Radamsa *(mutation input generator — produces test cases, not findings)*
- [~] Jazzer *(requires Java project and build integration — not a standalone CLI scanner)*
- [~] LibAFL *(Rust fuzzing framework / library — not a CLI tool)*

## Binary / Reverse Engineering

- [x] Binwalk *(firmware extraction and vulnerability analysis)*
- [x] checksec *(ELF/PE binary hardening checks — NX, PIE, RELRO, stack canary)*
- [~] Ghidra *(GUI reverse engineering tool — headless scripting exists but not a vulnerability scanner)*
- [~] Radare2 *(interactive analysis tool — no standalone vulnerability-scan mode)*
- [~] pwntools *(Python exploit development library — not a scanner)*
- [~] Cutter *(GUI application for Rizin — no CLI scan mode)*

## Threat Modeling

- [~] OWASP Threat Dragon *(web/desktop GUI — not a CLI scanner invocable against a target)*
- [~] PyTM *(Python library for writing threat models in code — not a scanner)*
- [~] Threatspec *(code annotation parser — generates docs, not scan findings)*

## API / Platform Integrations

- [~] BlackDuck API
- [~] Bugcrowd API
- [~] Cobalt API
- [~] EdgeScan API
- [~] HackerOne (H1)
- [~] Intsights
- [~] Risk Recon
- [~] SonarQube API
- [~] Trustwave Fusion API
- [~] Vulners API

## Generic / Multi-format

- [x] SARIF *(import reports in SARIF universal format)*
- [x] OpenSCAP *(XCCDF/OVAL compliance report import)*
- [x] Garak *(LLM security probe)*
- [~] PyRIT *(Python library — not a CLI tool invocable against a target)*
- [x] Promptmap *(automated prompt injection testing for LLM apps)*
- [~] JFrog Xray *(Artifactory integration)*
- [~] ReversingLabs SpectraAssure
- [~] Threat Composer *(AWS threat modeling)*
- [~] Xygeni
