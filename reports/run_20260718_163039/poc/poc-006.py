# poc-006: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:4280
# CWE: CWE-16
# Tool: wapiti
# Description: Connects to the lab target using TLS 1.2 with the specified cipher and prints the negotiated cipher and TLS version to confirm the server supports the cipher.
# Expected indicator: Cipher: ECDHE-ECDSA-AES128-SHA256
# Safe to run: True
# How to run: python3 poc-006.py

#!/usr/bin/env python3
import socket, ssl, sys

HOST = 'pentest-ground.com'
PORT = 4280
CIPHER = 'ECDHE-ECDSA-AES128-SHA256'

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers(CIPHER)
    except Exception as e:
        print('Warning: could not set cipher {}: {}'.format(CIPHER, e), file=sys.stderr)
    if hasattr(ssl, 'TLSVersion'):
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass
    try:
        with socket.create_connection((HOST, PORT), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as ssock:
                tls_ver = ssock.version()
                cipher = ssock.cipher()[0]
                cert = ssock.getpeercert()
                cn = None
                if cert and cert.get('subject'):
                    for r in cert.get('subject', ()):
                        for t in r:
                            if isinstance(t, tuple) and len(t) >= 2 and t[0] == 'commonName':
                                cn = t[1]
                                break
                        if cn:
                            break
                print('TLS Version: {}'.format(tls_ver))
                print('Cipher: {}'.format(cipher))
                print('Certificate CN: {}'.format(cn if cn else 'not detected'))
    except Exception as e:
        print('Connection failed: {}'.format(e), file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
