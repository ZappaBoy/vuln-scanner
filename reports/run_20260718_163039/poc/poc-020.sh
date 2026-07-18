# poc-020: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:9000
# CWE: CWE-200
# Tool: wapiti
# Description: Fetches the lab target's HTTPS response headers and reports whether the Strict-Transport-Security header is present to confirm HSTS is not set.
# Expected indicator: Strict-Transport-Security
# Safe to run: True
# How to run: bash poc-020.sh

#!/usr/bin/env bash
TARGET="https://pentest-ground.com:9000/"
RESPONSE=$(curl -sI -k "$TARGET" | tr -d '\\r')
if echo "$RESPONSE" | grep -qi '^Strict-Transport-Security:'; then
  echo "HSTS header detected in response header:"
  echo "$RESPONSE" | grep -i '^Strict-Transport-Security:'
  exit 0
else
  echo "HSTS header NOT detected on $TARGET. This confirms the TLS/HSTS misconfiguration (no HSTS)."
  exit 1
fi