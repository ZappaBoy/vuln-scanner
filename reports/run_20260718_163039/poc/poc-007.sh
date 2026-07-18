# poc-007: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:4280
# CWE: CWE-200
# Tool: wapiti
# Description: Confirms TLS negotiation uses the specified cipher and that the Strict-Transport-Security header is absent, indicating HSTS misconfiguration.
# Expected indicator: Cipher    : ECDHE-ECDSA-AES128-SHA256
# Safe to run: True
# How to run: bash poc-007.sh

#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="pentest-ground.com"
TARGET_PORT="4280"
TARGET_URL="https://${TARGET_HOST}:${TARGET_PORT}/"

echo "TLS/SSL PoC against ${TARGET_URL} (HSTS not set) - non-destructive"

# 1) Check TLS cipher via openssl s_client
CIPHER_OUTPUT=$(openssl s_client -connect "${TARGET_HOST}:${TARGET_PORT}" -servername "${TARGET_HOST}" -tls1_2 -cipher 'ECDHE-ECDSA-AES128-SHA256' </dev/null 2>&1 | grep -i '^Cipher' | head -n1 || true)
echo "$CIPHER_OUTPUT"

# 2) Check HSTS header via HTTP headers
HTTP_HEADERS=$(curl -sI --max-time 10 "${TARGET_URL}" || true)
HSTS_HEADER=$(echo "$HTTP_HEADERS" | tr -d '\r' | grep -i '^Strict-Transport-Security:' || true)
if [[ -n "${HSTS_HEADER}" ]]; then
  echo "HSTS detected: ${HSTS_HEADER}"
else
  echo "HSTS not detected in response headers"
fi

exit 0