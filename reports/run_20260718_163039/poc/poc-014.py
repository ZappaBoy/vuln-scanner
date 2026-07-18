# poc-014: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:5013
# CWE: CWE-200
# Tool: wapiti
# Description: If the script reports that the Strict-Transport-Security header is not present in the HTTPS response, it proves HSTS is not set for the target.
# Expected indicator: HSTS_NOT_SET
# Safe to run: True
# How to run: python3 poc-014.py

#!/usr/bin/env python3
import urllib.request
import ssl
import sys

TARGET = "https://pentest-ground.com:5013/"

def fetch_headers(url, verify=True, timeout=12):
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return dict(resp.headers)
    except Exception as e:
        return {"__error__": str(e)}


def main():
    url = TARGET
    headers = fetch_headers(url, verify=True)
    if "__error__" in headers:
        # try without verification if TLS cert issues
        headers = fetch_headers(url, verify=False)
    if "__error__" in headers:
        print("ERROR: Unable to fetch HTTPS headers: {}".format(headers["__error__"]))
        sys.exit(2)
    # look for HSTS header
    hsts_value = None
    for k, v in headers.items():
        if k.lower() == "strict-transport-security":
            hsts_value = v
            break
    if hsts_value:
        print("HSTS_SET: {}".format(hsts_value))
        sys.exit(0)
    else:
        print("HSTS_NOT_SET: No Strict-Transport-Security header found")
        sys.exit(0)


if __name__ == "__main__":
    main()
