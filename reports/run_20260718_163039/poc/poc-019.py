# poc-019: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:9000
# CWE: CWE-XXX
# Tool: wapiti
# Description: Confirms whether the target TLS certificate includes a Signed Certificate Timestamp (SCT) extension (Certificate Transparency).
# Expected indicator: CT_PRESENT=
# Safe to run: True
# How to run: python3 poc-019.py

#!/usr/bin/env python3
import subprocess
import tempfile
import os
import re


def main():
    host = "pentest-ground.com"
    port = "9000"
    openssl_cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-tls1_2",
        "-cipher", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
    ]

    try:
        proc = subprocess.run(openssl_cmd, input=b"", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
        output = proc.stdout.decode(errors="ignore").strip()
    except Exception as e:
        print("CT_PRESENT=NO")
        print(f"# TLS handshake failed: {e}")
        return

    certs = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.DOTALL)
    if not certs:
        print("CT_PRESENT=NO")
        print("# Certificate not found in OpenSSL s_client output.")
        return

    cert_pem = certs[0]

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tf:
        cert_path = tf.name
        tf.write(cert_pem.encode())
    try:
        x509_proc = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-text"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        x509_text = x509_proc.stdout.decode(errors="ignore")
    finally:
        try:
            os.remove(cert_path)
        except Exception:
            pass

    ct_present = False
    if "Signed Certificate Timestamp" in x509_text or "SignedCertificateTimestamp" in x509_text:
        ct_present = True
    if "1.3.6.1.4.1.11129.2.4.5" in x509_text:
        ct_present = True

    print(f"CT_PRESENT={'YES' if ct_present else 'NO'}")
    if ct_present:
        print("Certificate Transparency SCT extension detected in certificate.")
    else:
        print("Certificate Transparency SCT extension not detected; CT may not be enforced for this certificate.")


if __name__ == "__main__":
    main()
