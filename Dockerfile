FROM blackarchlinux/blackarch:latest

# Install system tools and security scanners in a single layer to minimise image size.
# Caches are purged in the same RUN to avoid bloat in intermediate layers.
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed \
        python python-pip unzip curl go cargo git jdk-openjdk \
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

# Install Go-based tools
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    ( go install github.com/trufflesecurity/jsluice/cmd/jsluice@latest 2>/dev/null || \
      ( curl -sL https://github.com/trufflesecurity/jsluice/releases/latest/download/jsluice_Linux_x86_64.tar.gz \
          -o /tmp/jsluice.tar.gz && \
        tar -xzf /tmp/jsluice.tar.gz -C /tmp jsluice && \
        mv /tmp/jsluice /usr/local/bin/jsluice && \
        rm -f /tmp/jsluice.tar.gz ) ) && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    cp /root/go/bin/httpx /root/go/bin/katana /root/go/bin/gosec /usr/local/bin/ 2>/dev/null || true && \
    cp /root/go/bin/jsluice /usr/local/bin/jsluice 2>/dev/null || true && \
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
        gvm-tools && \
    pip install --break-system-packages --no-cache-dir --no-deps apifuzzer

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
