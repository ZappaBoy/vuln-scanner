# poc-004: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:4280
# CWE: CWE-16
# Tool: wapiti
# Description: One sentence: Running an OpenSSL s_client TLS1.2 probe with a specific cipher against the target confirms whether the TLS cipher negotiation occurs as expected for the isolated lab host.
# Expected indicator: Negotiated cipher:
# Safe to run: True
# How to run: bash poc-004.sh

#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="pentest-ground.com"
TARGET_PORT="4280"
CIPHER="ECDHE-ECDSA-AES128-SHA256"

echo "[PoC] Testing TLS1.2 with cipher ${CIPHER} to ${TARGET_HOST}:${TARGET_PORT}"
RESPONSE=$(openssl s_client -connect "${TARGET_HOST}:${TARGET_PORT}" -tls1_2 -cipher "${CIPHER}" </dev/null 2>&1)

CIPHER_LINE=$(echo "$RESPONSE" | grep -i 'Cipher' | head -n1)

if [ -n "${CIPHER_LINE:-}" ]; then
  echo "Negotiated cipher: ${CIPHER_LINE}"
  exit 0
else
  echo "No Cipher line found; OpenSSL response did not negotiate the expected cipher."
  exit 1
fi