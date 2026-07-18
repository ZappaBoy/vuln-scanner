# poc-018: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:9000
# CWE: CWE-327
# Tool: wapiti
# Description: Confirms whether the server's TLS certificate includes the OCSP Must-Staple extension; absence proves the misconfiguration.
# Expected indicator: OCSP Must-Staple extension: absent
# Safe to run: True
# How to run: bash poc-018.sh

#!/usr/bin/env bash
set -euo pipefail
HOST="pentest-ground.com"
PORT="9000"
CIPHER="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
CERT_PEM=$(mktemp)
# Attempt to perform a TLS 1.2 handshake with the specified cipher and capture the server certificate
if ! timeout 10 openssl s_client -connect "${HOST}:${PORT}" -servername "${HOST}" -tls1_2 -cipher "${CIPHER}" </dev/null 2>/dev/null | awk '/-BEGIN CERTIFICATE-/{flag=1} flag{print} /-END CERTIFICATE-/{flag=0; exit}' > "${CERT_PEM}"; then
  echo "ERROR: Unable to retrieve server certificate from ${HOST}:${PORT} using TLS1.2 with cipher ${CIPHER}"
  rm -f "${CERT_PEM}"
  exit 1
fi

if [ ! -s "${CERT_PEM}" ]; then
  echo "ERROR: Certificate extraction failed; no certificate found."
  rm -f "${CERT_PEM}"
  exit 2
fi

CERT_TEXT=$(openssl x509 -in "${CERT_PEM}" -noout -text 2>/dev/null)
if echo "${CERT_TEXT}" | grep -qi "OCSP Must-Staple"; then
  STATUS="present"
else
  STATUS="absent"
fi

echo "OCSP Must-Staple extension: ${STATUS}"
rm -f "${CERT_PEM}"
exit 0