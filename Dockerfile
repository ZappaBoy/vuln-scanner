FROM blackarchlinux/blackarch:latest

# Install system tools and security scanners in a single layer to minimise image size.
# Caches are purged in the same RUN to avoid bloat in intermediate layers.
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed \
        python python-pip unzip curl go cargo git jdk-openjdk \
        make gcc \
        nodejs npm ruby \
        nmap nikto nuclei wapiti wpscan zaproxy arachni \
        sqlmap ffuf feroxbuster gobuster wfuzz \
        dalfox commix xsstrike nosqlmap \
        whatweb wafw00f hakrawler \
        arjun paramspider gau \
        testssl.sh sslyze sslscan tlsx \
        ssh-audit amass openvas \
        masscan rustscan subfinder dnsx dnsrecon \
        enum4linux-ng smbmap crackmapexec netdiscover \
        theharvester fierce naabu \
        kiterunner \
        trivy grype \
        semgrep bandit \
        checkov tfsec \
        gitleaks trufflehog && \
    pacman -Scc --noconfirm && \
    rm -rf /var/cache/pacman/pkg /tmp/pacman*

# Install Go-based tools (all in one layer; cache cleaned at the end)
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install github.com/aquasecurity/kube-bench@latest && \
    go install github.com/google/osv-scanner/cmd/osv-scanner@latest && \
    go install golang.org/x/vuln/cmd/govulncheck@latest && \
    go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true && \
    go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest && \
    go install github.com/edoardottt/cariddi/cmd/cariddi@latest && \
    go install github.com/d3mondev/puredns/v2@latest && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/tomnomnom/httprobe@latest && \
    ( go install github.com/sensepost/gowitness@latest 2>/dev/null || true ) && \
    ( go install github.com/trufflesecurity/jsluice/cmd/jsluice@latest 2>/dev/null || true ) && \
    find /root/go/bin -maxdepth 1 -type f -exec cp {} /usr/local/bin/ \; && \
    # Clean Go cache in the same layer
    go clean -cache -modcache && \
    rm -rf /root/go/pkg

# Install Python-based tools via pip (no caches)
RUN pip install --break-system-packages --no-cache-dir \
        CORScanner \
        graphql-cop \
        jsbeautifier \
        requests \
        pip-audit \
        gvm-tools \
        prowler \
        flawfinder \
        drheader \
        detect-secrets && \
    pip install --break-system-packages --no-cache-dir --no-deps apifuzzer

# Install terrascan (IaC scanner)
RUN TERRASCAN_URL=$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest \
        | grep '"browser_download_url"' | grep 'Linux_x86_64.tar.gz"' | head -1 | cut -d'"' -f4) && \
    [ -n "$TERRASCAN_URL" ] && \
    curl -sL "$TERRASCAN_URL" -o /tmp/terrascan.tar.gz && \
    tar -xzf /tmp/terrascan.tar.gz -C /usr/local/bin terrascan && \
    rm /tmp/terrascan.tar.gz || true

# Install hadolint (Dockerfile linter)
RUN curl -sLo /usr/local/bin/hadolint \
        https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && \
    chmod +x /usr/local/bin/hadolint

# Install bearer (SAST / data-flow scanner)
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin

# Install horusec (multi-language SAST)
RUN HORUSEC_URL=$(curl -s https://api.github.com/repos/ZupIT/horusec/releases/latest \
        | grep '"browser_download_url"' | grep 'linux_x64"' | head -1 | cut -d'"' -f4) && \
    [ -n "$HORUSEC_URL" ] && \
    curl -sLo /usr/local/bin/horusec "$HORUSEC_URL" && \
    chmod +x /usr/local/bin/horusec || true

# Install noseyparker (secret scanner, Rust binary)
RUN NOSEY_URL=$(curl -s https://api.github.com/repos/praetorian-inc/noseyparker/releases/latest \
        | grep '"browser_download_url"' | grep 'x86_64-unknown-linux' | grep '\.tar\.gz"' | head -1 | cut -d'"' -f4) && \
    [ -n "$NOSEY_URL" ] && \
    curl -sL "$NOSEY_URL" -o /tmp/noseyparker.tar.gz && \
    tar -xzf /tmp/noseyparker.tar.gz -C /tmp && \
    find /tmp -name 'noseyparker' -type f | head -1 | xargs -I{} mv {} /usr/local/bin/noseyparker && \
    chmod +x /usr/local/bin/noseyparker && \
    rm -f /tmp/noseyparker.tar.gz || true

# Install brakeman (Ruby on Rails SAST)
RUN gem install brakeman --no-document && \
    gem cleanup

# Install smuggler (HTTP request smuggling)
RUN git clone --depth 1 https://github.com/defparam/smuggler /opt/smuggler && \
    pip install --break-system-packages --no-cache-dir -r /opt/smuggler/requirements.txt 2>/dev/null || true && \
    printf '#!/bin/sh\nexec python3 /opt/smuggler/smuggler.py "$@"\n' > /usr/local/bin/smuggler && \
    chmod +x /usr/local/bin/smuggler && \
    rm -rf /opt/smuggler/.git

# Install LinkFinder (endpoint discovery in JS)
RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder /opt/LinkFinder && \
    pip install --break-system-packages --no-cache-dir -r /opt/LinkFinder/requirements.txt 2>/dev/null || true && \
    rm -rf /opt/LinkFinder/.git

# Install humble (HTTP header analyser) from source
RUN git clone --depth 1 https://github.com/rfc-st/humble /opt/humble && \
    pip install --break-system-packages --no-cache-dir -r /opt/humble/requirements.txt && \
    printf '#!/bin/sh\nexec python /opt/humble/humble.py "$@"\n' > /usr/local/bin/humble && \
    chmod +x /usr/local/bin/humble && \
    rm -rf /opt/humble/.git

# Install cherrybomb (Rust binary)
RUN cargo install cherrybomb && \
    cp /root/.cargo/bin/cherrybomb /usr/local/bin/cherrybomb && \
    rm -rf /root/.cargo/registry /root/.cargo/git

# Install SecretFinder script
RUN curl -sLo /usr/local/bin/SecretFinder \
        https://raw.githubusercontent.com/m4ll0k/SecretFinder/master/SecretFinder.py && \
    chmod +x /usr/local/bin/SecretFinder

# Install dependency-check (Java-based)
RUN pacman -S --noconfirm --needed dependency-check 2>/dev/null || \
    ( curl -sL https://github.com/jeremylong/DependencyCheck/releases/latest/download/dependency-check-linux.zip \
        -o /tmp/dc.zip && \
      unzip /tmp/dc.zip -d /opt && \
      ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check && \
      rm /tmp/dc.zip ) && \
    pacman -Scc --noconfirm

# Install TLS-Scanner (Java-based)
RUN TLS_URL=$(curl -s https://api.github.com/repos/tls-attacker/TLS-Scanner/releases/latest \
        | grep '"browser_download_url"' | grep '\.zip"' | head -1 | cut -d'"' -f4) && \
    [ -n "$TLS_URL" ] && \
    curl -sL "$TLS_URL" -o /tmp/tls-scanner.zip && \
    unzip -q /tmp/tls-scanner.zip -d /opt/tls-scanner && \
    JAR=$(find /opt/tls-scanner -name "*.jar" | head -1) && \
    printf "#!/bin/sh\nexec java -jar %s \"\$@\"\n" "$JAR" > /usr/local/bin/TLS-Scanner && \
    chmod +x /usr/local/bin/TLS-Scanner && \
    rm /tmp/tls-scanner.zip || true

# Install RESTler (.NET-based)
RUN RESTLER_URL=$(curl -s https://api.github.com/repos/microsoft/restler-fuzzer/releases/latest \
        | grep '"browser_download_url"' | grep -i 'linux' | head -1 | cut -d'"' -f4) && \
    [ -n "$RESTLER_URL" ] && \
    curl -sL "$RESTLER_URL" -o /tmp/restler.tar.gz && \
    mkdir -p /opt/restler && \
    tar -xzf /tmp/restler.tar.gz -C /opt/restler && \
    RESTLER_BIN=$(find /opt/restler -name "restler" -type f | head -1) && \
    [ -n "$RESTLER_BIN" ] && ln -sf "$RESTLER_BIN" /usr/local/bin/restler && \
    rm /tmp/restler.tar.gz || true

# Install uv (not in BlackArch repos)
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
