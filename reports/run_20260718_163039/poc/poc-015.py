# poc-015: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:5013
# CWE: CWE-310
# Tool: wapiti
# Description: Confirmation of TLS renegotiation support; if the server does not support secure renegotiation, it is vulnerable to MITM renegotiation attacks.
# Expected indicator: TLS renegotiation: not supported
# Safe to run: True
# How to run: python3 poc-015.py

#!/usr/bin/env python3
import subprocess, sys

HOST = 'pentest-ground.com'
PORT = '5013'
cmd = ['nmap', '-p', PORT, '--script', 'ssl-renegotiation', HOST]
try:
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
except Exception as e:
    print('ERROR: unable to run nmap:', e)
    sys.exit(1)
output = (res.stdout or '') + (res.stderr or '')
print(output)

line = None
for l in output.splitlines():
    if 'TLS renegotiation' in l:
        line = l.strip()
        break

if line:
    ll = line.lower()
    if 'not' in ll and 'supported' not in ll:
        print('VULNERABLE: server does not support secure TLS renegotiation')
    elif 'supported' in ll:
        print('NOT VULNERABLE: server supports TLS renegotiation')
    else:
        print('RENOG status unclear:', line)
else:
    print('RENOG status not detected in output')
