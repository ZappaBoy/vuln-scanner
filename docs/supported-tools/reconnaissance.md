# Reconnaissance

## Subdomain Enumeration

| Tool | Description |
|---|---|
| **Amass** | In-depth attack surface mapping and asset discovery combining active/passive DNS, certificate transparency, and 50+ API integrations. |
| **Subfinder** | Passive subdomain discovery tool by ProjectDiscovery aggregating results from 40+ sources. |
| **Findomain** | Fast cross-platform subdomain enumerator using certificate transparency logs and multiple passive APIs. |
| **Sublist3r** | Fast subdomains enumeration tool for penetration testers using multiple search engines and DNS brute-force. |
| **Massdns** | High-performance passive DNS bulk resolver for large-scale subdomain reconnaissance. |
| **Shuffledns** | Massdns wrapper with active bruteforce support and reliable wildcard/false-positive filtering. |
| **Puredns** | Fast, accurate DNS resolver with reliable wildcard detection and clean output; ideal for large wordlists. |
| **Dnsx** | Multi-purpose DNS toolkit by ProjectDiscovery for querying, brute-forcing, and chaining. |
| **Bbot** | Recursive internet scanner with 100+ modules covering subdomains, ports, web, and OSINT in a single run. |
| **Assetfinder** | Lightweight tool to find related domains and subdomains from passive sources (Wayback, crt.sh, Facebook, etc.). |
| **Subdominator** | Fast subdomain enumeration aggregating 50+ passive sources with de-duplication and validation. |
| **VHostScan** | Virtual host scanner with reverse lookup support to uncover hidden vhosts on shared IP addresses. |
| **github-subdomains** | Find subdomains by querying GitHub code search for domain mentions in repositories. |
| **csprecon** | Discover new domains and subdomains by analysing Content Security Policy headers. |
| **cero** | Scrape domain names from SSL/TLS certificates via live connections or saved certificate files. |
| **shosubgo** | Grab subdomains associated with a target using the Shodan API. |
| **haktrails** | Golang client for the SecurityTrails API for subdomain and DNS history reconnaissance. |
| **hakip2host** | Resolve IP address ranges to associated domain names via passive reverse DNS lookups. |

## DNS Permutation

| Tool | Description |
|---|---|
| **Alterx** | Fast, customizable subdomain wordlist generator by ProjectDiscovery using YAML-defined permutation patterns. |
| **Dnsgen** | Powerful DNS name permutation and mutation tool for expanding subdomain wordlists. |
| **Gotator** | DNS wordlist generator through permutations, mutations, and combination of known domain parts. |
| **Ripgen** | High-performance domain permutation generator written in Rust. |
| **Altdns** | Generates permutations and mutations of subdomains and resolves them to find new hosts. |

## Port Scanning

| Tool | Description |
|---|---|
| **Naabu** | Fast Go-based port scanner by ProjectDiscovery; designed to pair with Nuclei and other tools in pipelines. |
| **Masscan** | Fastest TCP port scanner — sends SYN packets asynchronously at millions of packets per second. |
| **RustScan** | Modern port scanner written in Rust; finds open ports in seconds then pipes into Nmap for service detection. |
| **Zmap** | Stateless large-scale internet-wide network scanner; can scan the full IPv4 space in under an hour. |

## URL & Endpoint Discovery

| Tool | Description |
|---|---|
| **gau** | Fetch all known URLs for a domain from Wayback Machine, CommonCrawl, and AlienVault OTX. |
| **Gauplus** | Extended URL gathering from Wayback, CommonCrawl, and OTX with added proxy and filter support. |
| **waybackurls** | Fetch all URLs that the Wayback Machine knows about for a given domain. |
| **waymore** | Extended Wayback Machine URL discovery with extra filtering and response downloading. |
| **Katana** | Next-generation web crawler and spidering framework by ProjectDiscovery with headless browser support. |
| **Hakrawler** | Fast, simple web crawler designed for easy discovery of endpoints and JavaScript-referenced assets. |
| **Gospider** | Fast web spider written in Go supporting sitemap, robots.txt, and JavaScript link extraction. |
| **xnLinkFinder** | Discover endpoints, parameters, and potential issues from HTTP responses and JavaScript files. |
| **LinkFinder** | Extract endpoints from JavaScript files using regex and AST analysis. |
| **JSluice** | Extract URLs, paths, secrets, and metadata from JavaScript source files. |
| **gf** | Wrapper around grep for quickly filtering URL lists for interesting parameters (SQLi, XSS, SSRF, etc.). |
| **uro** | De-duplicate and declutter URL lists for more efficient crawling and scanning. |
| **waybackurls** | Fetch known URLs from the Wayback Machine for passive recon. |
| **JSParser** | Parse relative URLs and endpoints from JavaScript files using Tornado and JSBeautifier. |
| **anew** | Append new lines from stdin to a file, skipping duplicates — essential for pipeline deduplication. |
| **unfurl** | Pull out bits of URLs (domains, paths, query params) from stdin for analysis and pivoting. |
| **httprobe** | Probe a list of domains for working HTTP and HTTPS servers; outputs only live hosts. |

## Parameter Discovery

| Tool | Description |
|---|---|
| **Arjun** | HTTP parameter discovery suite that brute-forces hidden GET and POST parameters. |
| **ParamSpider** | Mine parameters from web archives without interacting directly with the target. |
| **x8** | Hidden parameter discovery suite written in Rust with high-speed concurrent testing. |
| **param-miner** | Burp Suite extension that identifies hidden, unlinked parameters; also runs via Burp's headless API. |

## Screenshotting

| Tool | Description |
|---|---|
| **Gowitness** | Web screenshot utility using Chrome Headless; stores results with metadata in a SQLite database. |
| **EyeWitness** | Take screenshots of websites and provide server header info; supports HTTP, RDP, and VNC. |
| **Aquatone** | Visual inspection tool across large numbers of hosts; useful for quickly identifying interesting targets. |
| **WitnessMe** | Web inventory tool that takes screenshots using Pyppeteer and identifies default credentials. |

## OSINT

| Tool | Description |
|---|---|
| **theHarvester** | OSINT tool that gathers emails, subdomains, hosts, and employee names from public sources. |
| **SpiderFoot** | Automated OSINT framework with 200+ modules covering domains, IPs, emails, and data breaches. |
| **Photon** | Fast OSINT web crawler that extracts URLs, emails, files, API keys, and JavaScript links. |
| **ReconFTW** | Automated full-scope reconnaissance framework combining 35+ tools in a structured pipeline. |
| **BigBountyRecon** | Automates 58 different reconnaissance techniques using Google dorks and OSINT sources. |
| **Sn1per** | Automated pentest and recon framework combining 30+ tools for attack surface discovery. |
| **asnmap** | Map ASN (Autonomous System Numbers) to CIDR network ranges for organisation-wide recon. |
| **cvemap** | Modern CLI for exploring CVE data — filter by severity, product, EPSS, and KEV status. |
