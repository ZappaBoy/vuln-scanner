# poc-016: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:5013
# CWE: CWE-327
# Tool: wapiti
# Description: This script uses nmap ssl-renegotiation against pentest-ground.com port 5013 and reports VULNERABLE when the script indicates TLS renegotiation is exploitable.
# Expected indicator: VULNERABLE
# Safe to run: True
# How to run: bash poc-016.sh

#!/usr/bin/env bash
set -euo pipefail

HOST=pentest-ground.com
PORT=5013

if ! command -v nmap >/dev/null 2>&1; then
  echo \"ERROR: nmap not found in PATH\" >&2
  exit 3
fi

OUTPUT=$(nmap -p $PORT --script ssl-renegotiation $HOST 2>&1)

echo \"$OUTPUT\" 

if echo \"$OUTPUT\" | grep -qi VULNERABLE; then
  echo \"Result: VULNERABLE\"
  exit 0
elif echo \"$OUTPUT\" | grep -qi NOT_VULNERABLE; then
  echo \"Result: NOT_VULNERABLE\"
  exit 0
else
  echo \"Result: UNKNOWN\"
  exit 2
fi