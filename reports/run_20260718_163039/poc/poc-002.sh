# poc-002: Content Security Policy Configuration
# Target: https://pentest-ground.com:4280
# CWE: CWE-16
# Tool: wapiti
# Description: One-sentence: The script proves vulnerability by detecting either absence of a Content-Security-Policy header or its lack of the base-uri directive, indicating CSP is not enforced.
# Expected indicator: CSP_VULN_DETECTED
# Safe to run: True
# How to run: bash poc-002.sh

#!/usr/bin/env bash
set -euo pipefail
TARGET='https://pentest-ground.com:4280'
headers=$(curl -sI $TARGET 2>/dev/null)
if echo "$headers" | grep -qi '^Content-Security-Policy:'; then
  csp_line=$(echo "$headers" | grep -i '^Content-Security-Policy:' | head -n1)
  if echo "$csp_line" | grep -qi 'base-uri'; then
    echo "CSP_OK_BASE_URI_PRESENT"
  else
    echo "CSP_VULN_DETECTED"
  fi
else
  echo "CSP_VULN_DETECTED"
fi
