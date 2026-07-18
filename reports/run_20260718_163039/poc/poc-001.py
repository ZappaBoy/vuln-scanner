# poc-001: Content Security Policy Configuration
# Target: https://pentest-ground.com:4280
# CWE: CWE-XXX
# Tool: wapiti
# Description: Confirms whether the target returns a Content-Security-Policy header and whether that header includes the object-src directive; absence of object-src indicates the vulnerability.
# Expected indicator: object-src
# Safe to run: True
# How to run: python3 poc-001.py

#!/usr/bin/env python3
import sys
import urllib.request


def fetch_headers(url, timeout=10):
    req = urllib.request.Request(url, method='HEAD')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return dict((k.lower(), v) for k, v in resp.headers.items())
    except Exception:
        pass
    try:
        req = urllib.request.Request(url, headers={'Range': 'bytes=0-0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return dict((k.lower(), v) for k, v in resp.headers.items())
    except Exception:
        return None


def main():
    target = 'https://pentest-ground.com:4280'
    headers = fetch_headers(target)
    if not headers:
        print('No response from target or error fetching headers')
        sys.exit(2)
    csp_header = None
    for k, v in headers.items():
        if k.lower() == 'content-security-policy':
            csp_header = v
            break
    if not csp_header:
        print('Content-Security-Policy header not present')
        sys.exit(0)
    if 'object-src' in csp_header.lower():
        print('Content-Security-Policy header found with object-src directive')
        print('CSP value:', csp_header)
    else:
        print('Content-Security-Policy header present but missing object-src directive')
        print('CSP value:', csp_header)


if __name__ == '__main__':
    main()
