# poc-005: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:4280
# CWE: CWE-200
# Tool: wapiti
# Description: Connects to the lab target via TLS and reports whether OCSP stapling is present; OCSP response: no proves Must-Staple is not enforced.
# Expected indicator: OCSP response: no
# Safe to run: True
# How to run: bash poc-005.sh

#!/usr/bin/env bash
set -euo pipefail

HOST=pentest-ground.com
PORT=4280

OUTPUT=$(openssl s_client -connect "$HOST:$PORT" -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA256 </dev/null 2>&1 || true)

OCSP_LINE=$(printf "%s\n" "$OUTPUT" | grep -i 'OCSP response' || true)

echo "$OCSP_LINE"

if echo "$OCSP_LINE" | grep -qi 'OCSP response: no'; then
  echo 'OCSP stapling: missing (OCSP response: no)'
elif echo "$OCSP_LINE" | grep -qi 'OCSP response: yes'; then
  echo 'OCSP stapling: present'
else
  echo 'OCSP stapling: unknown (OCSP line not detected in output)'
fi
