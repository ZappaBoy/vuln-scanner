# poc-011: TLS/SSL misconfigurations
# Target: https://pentest-ground.com:5013
# CWE: CWE-200
# Tool: wapiti
# Description: One sentence: confirms via Nmap's ssl-renegotiation output whether the target supports secure TLS renegotiation (or not), indicating exposure to renegotiation-based information leakage.
# Expected indicator: Server supports secure renegotiation
# Safe to run: True
# How to run: python3 poc-011.py

#!/usr/bin/env python3
import subprocess, json


def main():
    host = "pentest-ground.com"
    port = 5013
    cmd = ["nmap", "-p", str(port), "--script", "ssl-renegotiation", host]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
        out = proc.stdout
    except Exception as e:
        out = "ERROR: {}".format(e)

    secure = None
    for line in out.splitlines():
        if "Server supports secure renegotiation" in line:
            if "Yes" in line:
                secure = True
            elif "No" in line:
                secure = False
            break

    if secure is True:
        summary = "Server supports secure TLS renegotiation."
    elif secure is False:
        summary = "Server does not support secure TLS renegotiation; vulnerable to TLS renegotiation attack."
    else:
        summary = "Renegotiation status could not be determined from ssl-renegotiation NSE output."

    data = {"host": host, "port": port, "summary": summary, "raw_output": out}
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
