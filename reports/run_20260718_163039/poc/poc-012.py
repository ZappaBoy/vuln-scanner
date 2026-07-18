# poc-012: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:5013
# CWE: CWE-XXX
# Tool: wapiti
# Description: This PoC runs the Nmap SSL Renegotiation script against the lab target and reports whether renegotiation is supported.
# Expected indicator: Renegotiation
# Safe to run: True
# How to run: python3 poc-012.py

#!/usr/bin/env python3

import subprocess, json, sys

TARGET_HOST = 'pentest-ground.com'
PORT = '5013'
CMD = ['nmap','-p',PORT,'--script','ssl-renegotiation',TARGET_HOST]
try:
    res = subprocess.run(CMD, capture_output=True, text=True, timeout=60)
except Exception as e:
    print(json.dumps({'error':'execution_error','detail':str(e)}))
    sys.exit(2)
stdout = res.stdout
stderr = res.stderr
exit_code = res.returncode
renegotiation_present = None
# Try to detect renegotiation status
if stdout:
    if 'Renegotiation' in stdout:
        renegotiation_present = True
    elif 'NOT' in stdout or 'NOT VULNERABLE' in stdout.upper():
        renegotiation_present = False
# Build output JSON for this PoC run
out = {
    'target': f'https://{TARGET_HOST}:{PORT}',
    'renegotiation_supported': renegotiation_present,
    'stdout': stdout,
    'stderr': stderr,
    'rc': exit_code
}
print(json.dumps(out))
