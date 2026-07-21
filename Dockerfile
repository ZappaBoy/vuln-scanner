FROM blackarchlinux/blackarch:latest

# ── Base system ──────────────────────────────────────────────────────────────
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed \
        jdk-openjdk git base-devel sudo python python-pip unzip curl \
        nodejs npm ruby go rust && \
    useradd -m -G wheel builder && \
    echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers && \
    git clone https://aur.archlinux.org/yay.git /tmp/yay && \
    chown -R builder:builder /tmp/yay && \
    su builder -c 'cd /tmp/yay && makepkg -si --noconfirm' && \
    rm -rf /tmp/yay

USER builder

# ── BlackArch / AUR packages ─────────────────────────────────────────────────
RUN yay -Syu --noconfirm && \
    yay -S --noconfirm --needed \
        nmap nikto nuclei wapiti wpscan zaproxy arachni sqlmap \
        ffuf feroxbuster gobuster wfuzz \
        dalfox commix xsstrike nosqlmap whatweb wafw00f \
        hakrawler arjun paramspider gau \
        testssl.sh sslyze sslscan tlsx \
        ssh-audit amass openvas masscan rustscan \
        subfinder dnsx dnsrecon enum4linux-ng smbmap crackmapexec netdiscover \
        theharvester fierce naabu kiterunner \
        trivy grype semgrep bandit checkov tfsec prowler flawfinder \
        gitleaks trufflehog httpx crlfuzz cariddi \
        puredns alterx waybackurls httprobe gowitness \
        osv-scanner govulncheck brakeman \
        detect-secrets noseyparker secretfinder \
        python-jsbeautifier python-requests dotnet-runtime \
        dependency-check restler-fuzzer \
        hadolint-bin terrascan-bin \
        hydra lynis subjack subzy tplmap checksec \
        jwt-tool gittools git-dumper h2csmuggler \
        kubescape-bin bbot kube-hunter \
        dirsearch joomscan whatwaf medusa cppcheck \
        clamav yara rkhunter chkrootkit binwalk \
        findomain massdns shuffledns spiderfoot \
        zmap ghauri  graphql-cop \
        dockle-bin \
        popeye-bin smuggler \
        assetfinder subover linkfinder retire second-order \
        gitjacker cmsmap syft wappalyzer-next-git \
        s3scanner zizmor parameth blackarch/jaeles python-witnessme && \
    yay -Scc --noconfirm

# ── Go tools ─────────────────────────────────────────────────────────────────
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install github.com/aquasecurity/kube-bench@latest && \
    go install github.com/BishopFox/jsluice/cmd/jsluice@latest && \
    go install github.com/devploit/nomore403@latest && \
    go install github.com/haccer/subjack@latest && \
    go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest && \
    go install github.com/gwen001/github-subdomains@latest && \
    go install github.com/hakluke/hakip2host@latest && \
    go install github.com/hakluke/haktrails@latest && \
    go install github.com/bp0lr/gauplus@latest && \
    go install github.com/d3mondev/puredns/v2@latest && \
    go install github.com/mhmdiaa/second-order@latest

RUN go install github.com/zricethezav/gitleaks/v8@latest && \
    go install github.com/sonatype-nexus-community/nancy@latest && \
    go clean -cache -modcache && \
    rm -rf ~/go/pkg

# ── Cargo (Rust) tools ───────────────────────────────────────────────────────
RUN cargo install cargo-audit && \
    cargo install ripgen && \
    rm -rf ~/.cargo/registry ~/.cargo/git ~/.cargo/.package-cache

USER root

# ── Promote builder binaries to system PATH ───────────────────────────────────
RUN find /home/builder/go/bin -maxdepth 1 -type f -exec cp {} /usr/local/bin/ \; && \
    find /home/builder/.cargo/bin -maxdepth 1 -type f -exec cp {} /usr/local/bin/ \; && \
    rm -rf /home/builder /var/cache/pacman/ /tmp/pacman*

# ── Ruby gems ────────────────────────────────────────────────────────────────
RUN gem install --no-document bundler-audit rubocop rubocop-ast \
        dawnscanner license_finder && \
    gem cleanup --silent && \
    rm -rf /root/.gem/ruby/*/cache /usr/lib/ruby/gems/*/cache

# ── Bearer ───────────────────────────────────────────────────────────────────
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin

# ── pip packages ─────────────────────────────────────────────────────────────
# Install each tool package individually — native-dep build failures are non-fatal.
# The app's own dependencies are installed later via `uv sync` and are unaffected.
RUN for pkg in \
        CORScanner drheader gvm-tools pip-audit \
        dnsgen waymore whispers \
        scoutsuite roadrecon s3scanner \
        xsrfprobe garak \
        quark-engine apkleaks qark \
        netaddr python-slugify; do \
        pip install --break-system-packages --no-cache-dir "$pkg" ; \
    done && \
    pip install --break-system-packages --no-cache-dir --no-deps apifuzzer 

# Tools not on PyPI — install from git source
RUN pip install --break-system-packages --no-cache-dir \
        git+https://github.com/Nefcore/CRLFsuite.git \
        git+https://github.com/codingo/VHostScan.git


# ── dnsreaper ────────────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/punk-security/dnsReaper /opt/dnsreaper && \
    pip install --break-system-packages --no-cache-dir -r /opt/dnsreaper/requirements.txt && \
    python3 -c "import glob; [open(p,'w').write(open(p).read().replace('from pkg_resources import get_distribution','from importlib.metadata import version as _iv\nget_distribution=lambda n:type(chr(95)+\"D\",(),{\"version\":_iv(n)})()')) for p in glob.glob('/usr/lib/python*/site-packages/google/cloud/dns/__init__.py')]" && \
    printf '#!/bin/sh\nexec python3 /opt/dnsreaper/main.py "$@"\n' > /usr/local/bin/dnsreaper && \
    chmod +x /usr/local/bin/dnsreaper && \
    rm -rf /opt/dnsreaper/.git

# ── git-dumper extra dep ──────────────────────────────────────────────────────
RUN pip install --break-system-packages --no-cache-dir requests_pkcs12

# ── humble ───────────────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/rfc-st/humble /opt/humble && \
    pip install --break-system-packages --no-cache-dir -r /opt/humble/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/humble/humble.py "$@"\n' > /usr/local/bin/humble && \
    chmod +x /usr/local/bin/humble && \
    rm -rf /opt/humble/.git

# ── TLS-Attacker ─────────────────────────────────────────────────────────────
RUN TLS_URL=$(curl -s https://api.github.com/repos/tls-attacker/TLS-Scanner/releases/latest \
        | grep '"browser_download_url"' | grep '\.zip"' | head -1 | cut -d'"' -f4) && \
    [ -n "$TLS_URL" ] && \
    curl -sL "$TLS_URL" -o /tmp/tls-scanner.zip && \
    unzip -q /tmp/tls-scanner.zip -d /opt/tls-scanner && \
    JAR=$(find /opt/tls-scanner -name "*.jar" | head -1) && \
    printf "#!/bin/sh\nexec java -jar %s \"\$@\"\n" "$JAR" > /usr/local/bin/TLS-Scanner && \
    chmod +x /usr/local/bin/TLS-Scanner && \
    rm /tmp/tls-scanner.zip

# ── Source-only tools ─────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/swisskyrepo/SSRFmap /opt/SSRFmap && \
    pip install --break-system-packages --no-cache-dir -r /opt/SSRFmap/requirements.txt && \
    rm -rf /opt/SSRFmap/.git

RUN git clone --depth 1 https://github.com/vladko312/SSTImap /opt/SSTImap && \
    pip install --break-system-packages --no-cache-dir -r /opt/SSTImap/requirements.txt && \
    rm -rf /opt/SSTImap/.git

RUN git clone --depth 1 https://github.com/s0md3v/Corsy /opt/Corsy && \
    rm -rf /opt/Corsy/.git

RUN git clone --depth 1 https://github.com/nahamsec/JSParser /opt/JSParser && \
    rm -rf /opt/JSParser/.git

RUN git clone --depth 1 https://github.com/1N3/BlackWidow /opt/blackwidow && \
    pip install --break-system-packages --no-cache-dir -r /opt/blackwidow/requirements.txt && \
    rm -rf /opt/blackwidow/.git

RUN git clone --depth 1 https://github.com/nikitastupin/csprecon /opt/csprecon && \
    pip install --break-system-packages --no-cache-dir /opt/csprecon  || \
    pip install --break-system-packages --no-cache-dir -r /opt/csprecon/requirements.txt  && \
    which csprecon  || \
    printf '#!/bin/sh\nexec python3 -m csprecon "$@"\n' > /usr/local/bin/csprecon && chmod +x /usr/local/bin/csprecon && \
    rm -rf /opt/csprecon/.git

RUN git clone --depth 1 https://github.com/nccgroup/ScoutSuite /opt/ScoutSuite && \
    pip install --break-system-packages --no-cache-dir -r /opt/ScoutSuite/requirements.txt && \
    rm -rf /opt/ScoutSuite/.git

RUN git clone --depth 1 https://github.com/aquasecurity/cloudsploit /opt/cloudsploit && \
    cd /opt/cloudsploit && npm install --no-audit --no-fund && npm cache clean --force && \
    printf '#!/bin/sh\nexec node /opt/cloudsploit/index.js "$@"\n' > /usr/local/bin/cloudsploit && \
    chmod +x /usr/local/bin/cloudsploit && \
    rm -rf /opt/cloudsploit/.git

RUN git clone --depth 1 https://github.com/s0md3v/Photon /opt/photon && \
    pip install --break-system-packages --no-cache-dir -r /opt/photon/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/photon/photon.py "$@"\n' > /usr/local/bin/photon && \
    chmod +x /usr/local/bin/photon && \
    rm -rf /opt/photon/.git

RUN git clone --depth 1 https://github.com/six2dez/reconftw /opt/reconftw && \
    chmod +x /opt/reconftw/reconftw.sh && \
    ln -sf /opt/reconftw/reconftw.sh /usr/local/bin/reconftw.sh && \
    rm -rf /opt/reconftw/.git

RUN git clone --depth 1 https://github.com/maaaaz/androwarn /opt/androwarn && \
    pip install --break-system-packages --no-cache-dir -r /opt/androwarn/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/androwarn/androwarn.py "$@"\n' > /usr/local/bin/androwarn && \
    chmod +x /usr/local/bin/androwarn && \
    rm -rf /opt/androwarn/.git

# ── Wrapper scripts for source-only Python tools ──────────────────────────────
# Always create the shim so the binary exists in PATH; if the git clone failed
# the underlying .py file will be missing and the error surfaces at scan time.
RUN for spec in \
        "aemhacker:/opt/aemhacker/aem_hacker.py" \
        "blackwidow:/opt/blackwidow/blackwidow.py" \
        "oralyzer:/opt/oralyzer/oralyzer.py"; do \
    name="${spec%%:*}"; path="${spec##*:}"; \
    printf '#!/bin/sh\nexec python3 %s "$@"\n' "$path" > "/usr/local/bin/$name" && \
        chmod +x "/usr/local/bin/$name"; \
done

# ── Joern (requires JVM) ─────────────────────────────────────────────────────
RUN JOERN_VER=$(curl -s https://api.github.com/repos/joernio/joern/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$JOERN_VER" ] && \
    curl -sL "https://github.com/joernio/joern/releases/download/${JOERN_VER}/joern-install.sh" \
         -o /tmp/joern-install.sh && \
    chmod +x /tmp/joern-install.sh && \
    /tmp/joern-install.sh --prefix /opt/joern  && \
    ln -sf /opt/joern/joern-cli/joern /usr/local/bin/joern

# ── PMD (Java SAST) ──────────────────────────────────────────────────────────
RUN PMD_VER=$(curl -s https://api.github.com/repos/pmd/pmd/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | sed 's/pmd_releases\///') && \
    [ -n "$PMD_VER" ] && \
    curl -sL "https://github.com/pmd/pmd/releases/download/pmd_releases/${PMD_VER}/pmd-dist-${PMD_VER}-bin.zip" \
         -o /tmp/pmd.zip && \
    unzip -q /tmp/pmd.zip -d /opt/ && \
    mv /opt/pmd-bin-${PMD_VER} /opt/pmd && \
    ln -sf /opt/pmd/bin/pmd /usr/local/bin/pmd && \
    rm /tmp/pmd.zip

# ── SpotBugs (Java) ──────────────────────────────────────────────────────────
RUN SB_VER=$(curl -s https://api.github.com/repos/spotbugs/spotbugs/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$SB_VER" ] && \
    curl -sL "https://github.com/spotbugs/spotbugs/releases/download/${SB_VER}/spotbugs-${SB_VER}.tgz" \
         -o /tmp/spotbugs.tgz && \
    tar -xf /tmp/spotbugs.tgz -C /opt/ && \
    mv /opt/spotbugs-${SB_VER} /opt/spotbugs && \
    ln -sf /opt/spotbugs/bin/spotbugs /usr/local/bin/spotbugs && \
    rm /tmp/spotbugs.tgz

# ── CodeQL CLI ───────────────────────────────────────────────────────────────
RUN CQL_VER=$(curl -s https://api.github.com/repos/github/codeql-action/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$CQL_VER" ] && \
    curl -sL "https://github.com/github/codeql-action/releases/download/${CQL_VER}/codeql-bundle-linux64.tar.gz" \
         -o /tmp/codeql.tar.gz && \
    tar -xf /tmp/codeql.tar.gz -C /opt/ && \
    ln -sf /opt/codeql/codeql /usr/local/bin/codeql && \
    rm /tmp/codeql.tar.gz

# ── SpiderFoot CLI shortcut ───────────────────────────────────────────────────
# The BlackArch spiderfoot package puts the CLI scanner at sf.py; expose it as `sf`.
RUN SF_PY=$(find /usr/share/spiderfoot /usr/lib/spiderfoot -name "sf.py"  | head -1) && \
    [ -n "$SF_PY" ] && \
        printf '#!/bin/sh\nexec python3 %s "$@"\n' "$SF_PY" > /usr/local/bin/sf && \
        chmod +x /usr/local/bin/sf

# ── Threagile ────────────────────────────────────────────────────────────────
RUN THREAGILE_VER=$(curl -s https://api.github.com/repos/Threagile/threagile/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$THREAGILE_VER" ] && \
    curl -sL "https://github.com/Threagile/threagile/releases/download/${THREAGILE_VER}/threagile-linux-amd64" \
         -o /usr/local/bin/threagile && \
    chmod +x /usr/local/bin/threagile

# ── MVT (Mobile Verification Toolkit) ────────────────────────────────────────
RUN pip install --break-system-packages --no-cache-dir mvt 

# ── uv ───────────────────────────────────────────────────────────────────────
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    ln -sf /root/.local/bin/uv /usr/local/bin/uv

# ── Final image cleanup ───────────────────────────────────────────────────────
# Removes cross-layer debris that couldn't be cleaned in the same layer it was
# created (e.g. .pyc files generated during imports, shared man/doc directories).
# This doesn't reclaim space in previously committed layers, but it eliminates
# these files from every layer written after this point (COPY, uv sync, etc.).
RUN find /opt -maxdepth 2 -name ".git" -type d -exec rm -rf {} +  && \
    find /usr /usr/local -path "*/__pycache__" -type d -exec rm -rf {} + && \
    find /usr /usr/local -name "*.pyc" -o -name "*.pyo" | xargs rm -f  && \
    rm -rf /usr/share/man /usr/share/doc /usr/share/gtk-doc /usr/share/info \
           /root/.cache /root/.npm /root/.local/share/gem \
           /tmp/* /var/tmp/*

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