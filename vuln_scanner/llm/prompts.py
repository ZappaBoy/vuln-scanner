"""Default prompt templates for LLM analysis passes.

All templates support {placeholder} substitution. Users can override any template
via config [llm.prompts] to fully customise the LLM behaviour.
"""

ENRICH_SYSTEM = """\
You are a penetration tester triaging and remediating automated scanner findings.
Be terse and technical. Return ONLY valid JSON — no markdown fences, no commentary outside the JSON.
"""

ENRICH_USER = """\
Triage and remediate this finding from tool '{tool}' on target '{target}'.

Title: {title}
Severity: {severity}
Description: {description}
CVEs: {cves}
Raw output: {raw_output}

Return JSON with exactly these keys:
{{
  "cwe": ["CWE-XXX"],
  "confidence": "high|medium|low|unknown",
  "false_positive": true|false|null,
  "exploitability": "1-2 sentences — attacker steps and prerequisite access only",
  "notes": "1 sentence analyst context",
  "cvss_vector": "CVSS:3.1/AV:...",
  "cvss_score": 0.0,
  "poc_plan": "one-liner: CLI tool + flag + target that proves this, or empty string",
  "mitigation": "immediate workaround — 2-4 numbered steps, commands/config only (under 200 words)",
  "remediation": "permanent fix — 2-4 numbered steps, commands/config only (under 200 words)"
}}
"""

CLUSTER_SYSTEM = """\
You are a senior pentester writing a client report. Be concise and technical.
Return ONLY valid JSON — no markdown fences, no commentary outside the JSON.
"""

CLUSTER_USER = """\
Cluster these findings by root cause. Findings:
{findings_json}

Return JSON:
{{
  "clusters": [
    {{
      "id": "cluster-N",
      "title": "short title",
      "severity": "critical|high|medium|low|info",
      "summary": "2 sentences: root cause and exploitation path",
      "member_titles": ["exact title", ...],
      "shared_remediation": "2-3 bullet points, concrete actions only",
      "tags": ["tag", ...]
    }}
  ],
  "executive_summary": "3 sentences: what was found, business risk, top priority action"
}}
"""

MITIGATION_SYSTEM = """\
You are writing the remediation section of a pentest report. Be direct and actionable.
Return ONLY valid JSON — no markdown fences, no commentary outside the JSON.
"""

MITIGATION_USER = """\
Write remediation for this finding.
{poc_evidence}

Title: {title}
Severity: {severity}
Description: {description}
CWE: {cwe}
Exploitability: {exploitability}
Tool: {tool} / Target: {target}

Return JSON with exactly these keys. Keep each field under 300 words.
Use numbered lists and fenced code blocks (```lang\\n...\\n```) where helpful.
{{
  "mitigation": "immediate workaround — 2-4 numbered steps, commands/config only",
  "remediation": "permanent fix — 2-4 numbered steps, commands/config only"
}}
"""

POC_SYSTEM = """\
You are writing PoC scripts for a BlackArch container that has:
curl, wget, python3, nmap, sqlmap, nuclei, dalfox, ffuf, feroxbuster, nikto, gobuster,
commix, wfuzz, xsstrike, sslyze, sslscan, testssl.sh, amass, subfinder, dnsx, naabu,
smbmap, enum4linux-ng, crackmapexec, semgrep, bandit, trivy, grype, gitleaks, trufflehog.
Write minimal, non-destructive confirmation scripts only.
Return ONLY valid JSON — no markdown fences, no commentary outside the JSON.
"""

POC_USER = """\
Write a PoC for this finding against an isolated lab target.

Title: {title}
Severity: {severity}
Description: {description}
CWE: {cwe}
Exploitability: {exploitability}
PoC plan: {poc_plan}
Target: {target}

{git_clone_instruction}

Return JSON:
{{
  "language": "python|bash",
  "script": "complete self-contained script",
  "description": "one sentence: what confirmed output proves",
  "expected_indicator": "string to look for in output",
  "safe_to_run": true|false,
  "safety_notes": ""
}}

Rules: non-destructive only, test only {target}, no persistence/exfiltration/lateral movement.
"""
