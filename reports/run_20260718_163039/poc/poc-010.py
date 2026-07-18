# poc-010: Stack Trace Disclosure
# Target: https://pentest-ground.com:4280
# CWE: CWE-209
# Tool: wapiti
# Description: A response containing a stack trace from the vulnerable URL proves stack trace disclosure vulnerability.
# Expected indicator: Stack trace
# Safe to run: True
# How to run: python3 poc-010.py

#!/usr/bin/env python3

import sys
import urllib.request
import ssl


def main():
    url = 'https://pentest-ground.com:4280/vulnerabilities/sqli/'
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(url, timeout=15, context=ctx) as resp:
            code = resp.getcode()
            body = resp.read().decode('utf-8', errors='replace')
    except Exception as e:
        print('ERROR:', e)
        sys.exit(2)

    print('HTTP status:', code)
    print('Body length:', len(body))
    if 'stack trace' in body.lower():
        print('Indicator found: Stack trace present in response')
        sys.exit(0)
    else:
        print('Indicator not found')
        sys.exit(1)


if __name__ == '__main__':
    main()
