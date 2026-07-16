"""Default prompt templates for LLM analysis passes.

All templates support {placeholder} substitution. Users can override any template
via config [llm.prompts] to fully customise the LLM behaviour.
"""

ENRICH_SYSTEM = """\
You are an expert penetration tester and vulnerability analyst. Your task is to triage
security findings from automated scanning tools. Return ONLY valid JSON — no markdown fences,
no commentary outside the JSON.
"""

ENRICH_USER = """\
Analyze the following security finding from tool '{tool}' against target '{target}'.

Finding:
  Title: {title}
  Severity: {severity}
  Description: {description}
  CVEs: {cves}
  Tool raw output (truncated): {raw_output}

Return a JSON object with exactly these keys:
{{
  "cwe": ["CWE-XXX"],          // list of applicable CWE IDs, empty list if none
  "confidence": "high|medium|low|unknown",
  "false_positive": true|false|null,  // null = cannot determine
  "exploitability": "brief 1-2 sentence assessment of how easy this is to exploit in practice",
  "notes": "brief analyst note explaining the severity and context",
  "poc_plan": "concise description of a PoC script that would confirm/exploit this finding using CLI tools (curl, sqlmap, nuclei, etc.) or Python — or empty string if not applicable"
}}
"""

CLUSTER_SYSTEM = """\
You are a senior security consultant producing a structured vulnerability assessment.
Return ONLY valid JSON — no markdown fences, no commentary outside the JSON.
"""

CLUSTER_USER = """\
Group the following security findings into root-cause clusters for a professional report.
Findings (JSON array):
{findings_json}

Return a JSON object with exactly these keys:
{{
  "clusters": [
    {{
      "id": "cluster-1",
      "title": "short cluster title",
      "severity": "critical|high|medium|low|info",
      "summary": "2-3 sentence root-cause description",
      "member_titles": ["exact finding title", ...],
      "shared_remediation": "concrete remediation steps shared by all members",
      "tags": ["injection", "auth", ...]
    }}
  ],
  "executive_summary": "3-5 sentence executive summary suitable for a client report"
}}
"""

MITIGATION_SYSTEM = """\
You are a senior penetration tester writing a professional vulnerability report.
Return ONLY valid JSON — no markdown fences, no commentary outside the JSON.
"""

MITIGATION_USER = """\
Write a detailed mitigation and remediation plan for the following finding.
{poc_evidence}

Finding:
  Title: {title}
  Severity: {severity}
  Description: {description}
  CWE: {cwe}
  Exploitability: {exploitability}
  Tool: {tool}
  Target: {target}

Return a JSON object with exactly these keys:
{{
  "mitigation": "immediate mitigation steps (short-term workarounds). Use Markdown formatting: numbered lists, bold for key terms, and fenced code blocks (```language ... ```) for any config or command examples.",
  "remediation": "permanent fix with concrete implementation steps. Use Markdown formatting: numbered lists, bold for key terms, and fenced code blocks (```language ... ```) for any config, code, or command examples."
}}
"""

POC_SYSTEM = """\
You are a penetration tester writing proof-of-concept exploit scripts.
The scripts will run inside a BlackArch Linux Docker container that has these tools available:
curl, wget, python3, nmap, sqlmap, nuclei, dalfox, ffuf, feroxbuster, nikto, gobuster,
commix, wfuzz, xsstrike, sslyze, sslscan, testssl.sh, amass, subfinder, dnsx, naabu,
smbmap, enum4linux-ng, crackmapexec, semgrep, bandit, trivy, grype, gitleaks, trufflehog.
Write ONLY self-contained, non-destructive scripts that CONFIRM the vulnerability exists.
Return ONLY valid JSON — no markdown fences, no commentary outside the JSON.
"""

POC_USER = """\
Write a proof-of-concept script for the following vulnerability finding.
The target is an isolated lab environment (intentionally vulnerable container).

Finding:
  Title: {title}
  Severity: {severity}
  Description: {description}
  CWE: {cwe}
  Exploitability: {exploitability}
  PoC plan: {poc_plan}
  Target: {target}

{git_clone_instruction}

Return a JSON object with exactly these keys:
{{
  "language": "python|bash",
  "script": "complete self-contained script as a string",
  "description": "what this PoC proves and how to interpret its output",
  "expected_indicator": "string that appears in output when vulnerability is confirmed",
  "safe_to_run": true|false,
  "safety_notes": "any caveats (empty string if fully safe)"
}}

CRITICAL RULES:
- Script must be NON-DESTRUCTIVE: no data deletion, no DoS, no fork bombs, no system-wide changes
- Only test the specific target provided ({target})
- No lateral movement, no persistence, no exfiltration of data outside the container
- If you cannot write a safe PoC, set safe_to_run to false and explain in safety_notes
"""
