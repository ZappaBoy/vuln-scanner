FROM blackarchlinux/blackarch:latest

RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed jdk-openjdk && \
    pacman -S --noconfirm --needed git base-devel sudo python python-pip unzip curl git nodejs npm ruby go && \
    useradd -m -G wheel builder && \
    echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers && \
    git clone https://aur.archlinux.org/yay.git /tmp/yay && \
    chown -R builder:builder /tmp/yay && \
    su builder -c 'cd /tmp/yay && makepkg -si --noconfirm' && \
    rm -rf /tmp/yay

USER builder

RUN yay -Syu --noconfirm && \
    yay -S --noconfirm --needed \
        nmap nikto nuclei wapiti wpscan zaproxy arachni sqlmap ffuf feroxbuster gobuster wfuzz \
        dalfox commix xsstrike nosqlmap whatweb wafw00f hakrawler arjun paramspider gau testssl.sh sslyze sslscan tlsx \
        ssh-audit amass openvas masscan rustscan subfinder dnsx dnsrecon enum4linux-ng smbmap crackmapexec netdiscover \
        theharvester fierce naabu kiterunner trivy grype semgrep bandit checkov tfsec prowler flawfinder gitleaks \
        trufflehog httpx crlfuzz cariddi puredns alterx waybackurls httprobe gowitness osv-scanner govulncheck \
        brakeman smuggler linkfinder graphql-cop detect-secrets python-jsbeautifier python-requests dotnet-runtime \
        hadolint-bin terrascan-bin noseyparker secretfinder dependency-check restler-fuzzer hydra lynis subjack subzy \
        tplmap checksec jwt-tool gittools git-dumper h2csmuggler kubescape-bin bbot kube-hunter && \
    yay -Scc --noconfirm

RUN go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install github.com/aquasecurity/kube-bench@latest && \
    ( go install github.com/trufflesecurity/jsluice/cmd/jsluice@latest 2>/dev/null || true ) && \
    go install github.com/devploit/nomore403@latest && \
    go clean -cache -modcache && \
    rm -rf /home/builder/go/pkg

USER root

RUN find /home/builder/go/bin -maxdepth 1 -type f -exec cp {} /usr/local/bin/ \; && \
    rm -rf /var/cache/pacman/ /tmp/pacman* \
           /home/builder/.cache/go-build \
           /home/builder/.cache/yay \
           /home/builder/.cache/yay-bin

# bearer
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin

# cherrybomb
RUN CHERRY_URL=$(curl -s https://api.github.com/repos/blst-security/cherrybomb/releases/latest \
        | grep '"browser_download_url"' | grep -i 'linux' | grep -v '\.sha' | head -1 | cut -d'"' -f4) && \
    [ -n "$CHERRY_URL" ] && \
    curl -sLo /usr/local/bin/cherrybomb "$CHERRY_URL" && \
    chmod +x /usr/local/bin/cherrybomb || true

RUN pip install --break-system-packages --no-cache-dir \
        CORScanner \
        drheader \
        gvm-tools \
        pip-audit \
        humble && \
    pip install --break-system-packages --no-cache-dir --no-deps apifuzzer

# dnsreaper — google-cloud-dns uses pkg_resources which was dropped from setuptools 75+.
# Patch the installed file to use importlib.metadata instead (available since Python 3.8).
RUN git clone --depth 1 https://github.com/punk-security/dnsReaper /opt/dnsreaper && \
    pip install --break-system-packages --no-cache-dir -r /opt/dnsreaper/requirements.txt && \
    python3 -c "import glob; [open(p,'w').write(open(p).read().replace('from pkg_resources import get_distribution','from importlib.metadata import version as _iv\nget_distribution=lambda n:type(chr(95)+\"D\",(),{\"version\":_iv(n)})()')) for p in glob.glob('/usr/lib/python*/site-packages/google/cloud/dns/__init__.py')]" && \
    printf '#!/bin/sh\nexec python3 /opt/dnsreaper/main.py "$@"\n' > /usr/local/bin/dnsreaper && \
    chmod +x /usr/local/bin/dnsreaper && \
    rm -rf /opt/dnsreaper/.git

# git-dumper — requests_pkcs12 is an optional dep not listed in its install_requires
RUN pip install --break-system-packages --no-cache-dir requests_pkcs12

# humble
RUN git clone --depth 1 https://github.com/rfc-st/humble /opt/humble && \
    pip install --break-system-packages --no-cache-dir -r /opt/humble/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/humble/humble.py "$@"\n' > /usr/local/bin/humble && \
    chmod +x /usr/local/bin/humble && \
    rm -rf /opt/humble/.git

RUN TLS_URL=$(curl -s https://api.github.com/repos/tls-attacker/TLS-Scanner/releases/latest \
        | grep '"browser_download_url"' | grep '\.zip"' | head -1 | cut -d'"' -f4) && \
    [ -n "$TLS_URL" ] && \
    curl -sL "$TLS_URL" -o /tmp/tls-scanner.zip && \
    unzip -q /tmp/tls-scanner.zip -d /opt/tls-scanner && \
    JAR=$(find /opt/tls-scanner -name "*.jar" | head -1) && \
    printf "#!/bin/sh\nexec java -jar %s \"\$@\"\n" "$JAR" > /usr/local/bin/TLS-Scanner && \
    chmod +x /usr/local/bin/TLS-Scanner && \
    rm /tmp/tls-scanner.zip || true

RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    ln -sf /root/.local/bin/uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --no-dev --no-install-project && \
    uv cache clean

COPY . .
RUN uv sync --no-dev && \
    uv cache clean && \
    rm -rf /tmp/*

# Safety marker — PoC execution is only permitted inside this container.
# The poc/runner.py checks for this env var and refuses to execute otherwise.
ENV VS_IN_CONTAINER=1

ENTRYPOINT ["uv", "run", "vuln-scanner"]
