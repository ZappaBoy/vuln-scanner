# poc-009: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:4280
# CWE: CWE-327
# Tool: wapiti
# Description: Performs TLS1.2 handshakes against the lab target using CBC-based ECDHE ciphers and reports whether a CBC cipher is negotiated.
# Expected indicator: CBC_Cipher_Negotiated: YES
# Safe to run: True
# How to run: python3 poc-009.py

#!/usr/bin/env python3

import subprocess
host = 'pentest-ground.com'
port = 4280
ciphers = ['ECDHE-ECDSA-AES128-SHA256', 'ECDHE-ECDSA-AES256-SHA384']
cbc_negotiated = 'NO'
for c in ciphers:
    print(f'Trying CBC cipher: {c}')
    try:
        out = subprocess.check_output(['openssl', 's_client', '-connect', f'{host}:{port}', '-tls1_2', '-servername', host, '-cipher', c], timeout=5, stderr=subprocess.STDOUT)
    except Exception:
        out = b''
    s = out.decode('utf-8', 'ignore')
    cipher_line = None
    for line in s.splitlines():
        if line.strip().lower().startswith('cipher'):
            cipher_line = line.strip()
            print(cipher_line)
            if 'cbc' in cipher_line.lower():
               cbc_negotiated = 'YES'
            break
    if cipher_line is None:
        print('Handshake might have failed or no cipher negotiated for this cipher.')
    if cbc_negotiated == 'YES':
        break
print('CBC_Cipher_Negotiated: {}'.format(cbc_negotiated))
