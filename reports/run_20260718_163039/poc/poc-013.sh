# poc-013: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:5013
# CWE: CWE-326
# Tool: wapiti
# Description: Run an Nmap ssl-renegotiation probe against the target to determine if TLS renegotiation is vulnerable.
# Expected indicator: vulnerable
# Safe to run: True
# How to run: bash poc-013.sh

#!/usr/bin/env bash
set -euo pipefail
TARGET=pentest-ground.com
PORT=5013
if ! command -v nmap >/dev/null; then echo 'ERROR: nmap not found'; exit 1; fi
OUTPUT=$(nmap -p 5013 --script ssl-renegotiation pentest-ground.com 2>&1 || true)
echo "$OUTPUT"
if echo "$OUTPUT" | grep -qi 'vulnerable'; then
  echo 'VULNERABLE: TLS renegotiation is allowed on the target'
elif echo "$OUTPUT" | grep -qiE 'not vulnerable|not supported|blocked'; then
  echo 'NOT_VULNERABLE: TLS renegotiation appears blocked on the target'
else
  echo 'UNKNOWN: Unable to determine renegotiation status from output'
fi