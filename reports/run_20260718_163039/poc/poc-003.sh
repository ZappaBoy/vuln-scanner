# poc-003: Content Security Policy Configuration
# Target: https://pentest-ground.com:4280
# CWE: CWE-16
# Tool: wapiti
# Description: One sentence: the script confirms whether CSP-related headers are present in the server response, indicating CSP configuration status.
# Expected indicator: Presence of any of the headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, or Strict-Transport-Security
# Safe to run: True
# How to run: bash poc-003.sh

#!/usr/bin/env bash

TARGET="https://pentest-ground.com:4280"; headers=$(curl -sI "$TARGET" | tr -d '\r'); echo "$headers" | sed 's/^/HEADER: /'; match=$(echo "$headers" | grep -i -E 'Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security'); if [ -n "$match" ]; then echo "Found CSP-related header(s):"; echo "$match"; else echo "No CSP-related headers found in the response."; fi