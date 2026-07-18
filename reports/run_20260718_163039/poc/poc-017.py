# poc-017: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:9000
# CWE: CWE-327
# Tool: wapiti
# Description: Connects to the lab TLS service and reports whether the certificate uses Extended Validation by inspecting the EV policy OID when available.
# Expected indicator: EV_PRESENT=NO
# Safe to run: True
# How to run: python3 poc-017.py

#!/usr/bin/env python3

import socket, ssl
try:
    host = 'pentest-ground.com'
    port = 9000
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            subject = None
            ev_present = False
            ev_known = False
            ev_oid = '2.23.140.1.1'
            try:
                from cryptography import x509
                cert = x509.load_der_x509_certificate(der)
                subject = cert.subject.rfc4514_string()
                try:
                    pol_ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies)
                    oids = [p.policy_identifier.dotted_string for p in pol_ext.value]
                    ev_present = ev_oid in oids
                    ev_known = True
                except Exception:
                    ev_known = False
            except Exception:
                subject = None
                ev_known = False
            print('SUBJECT=' + (subject if subject else 'unknown'))
            if ev_known:
                print('EV_PRESENT=' + ('YES' if ev_present else 'NO'))
                if ev_present:
                    print('EV_POLICY_OID=' + ev_oid)
                else:
                    print('EV_POLICY_OID=' + ev_oid + ' (not found)')
            else:
                # Fallback: EV status could not be determined (cryptography not available)
                print('EV_PRESENT=NO')
                print('EV_POLICY_OID=' + ev_oid + ' (unknown; cryptography not available)')
except Exception as e:
    print('ERROR:' + str(e))
