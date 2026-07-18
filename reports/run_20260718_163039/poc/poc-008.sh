# poc-008: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:4280
# CWE: CWE-327
# Tool: wapiti
# Description: One sentence: it proves whether the TLS server advertises secure renegotiation; if the output shows Secure Renegotiation: no, the server does not support secure renegotiation.
# Expected indicator: Secure Renegotiation: no
# Safe to run: True
# How to run: bash poc-008.sh

#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="pentest-ground.com"
TARGET_PORT="4280"
TARGET_URL="https://${TARGET_HOST}:${TARGET_PORT}"

echo "Target: ${TARGET_URL}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found in PATH" >&2
  exit 3
fi

OUTPUT=$(openssl s_client -connect ${TARGET_HOST}:${TARGET_PORT} -tls1_2 -cipher 'ECDHE-ECDSA-AES128-SHA256' </dev/null 2>&1 || true)

CipherLine=$(echo "${OUTPUT}" | grep -i '^Cipher' || true)
RenegLine=$(echo "${OUTPUT}" | grep -i 'Secure Renegotiation' || true)

if [ -n "${CipherLine}" ]; then
  echo "Cipher line: ${CipherLine}"
fi
if [ -n "${RenegLine}" ]; then
  echo "Renegotiation line: ${RenegLine}"
else
  echo "Renegotiation line: not reported by OpenSSL"
fi

if echo "${OUTPUT}" | grep -qi 'Secure Renegotiation: no'; then
  echo "VULN_DETECTED: Secure Renegotiation is not supported by the server"
  exit 0
else
  echo "INFO: Secure Renegotiation appears supported or information not explicit"
  exit 0
fi
