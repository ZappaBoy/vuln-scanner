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
# Using || true so that packages unavailable in the current repo don't abort
# the build; tools gracefully report ScanStatus.FAILED at runtime when missing.
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
        zmap ghauri weggli kics graphql-cop \
        syft-bin dockle-bin kubeaudit-bin kube-score-bin kube-linter-bin \
        popeye-bin dive-bin insider-bin smuggler \
        knockpy assetfinder subover subdominator linkfinder retire second-order \
        tko-subs gitjacker jaeles-bin cmsmap syft wappalyzer-next-git \
        gotator s3scanner regula zizmor parameth 2>&1 || true && \
    yay -Scc --noconfirm

# ── Go tools ─────────────────────────────────────────────────────────────────
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest 2>/dev/null || true && \
    go install github.com/aquasecurity/kube-bench/cmd/kube-bench@latest 2>/dev/null || true && \
    go install github.com/trufflesecurity/jsluice/cmd/jsluice@latest 2>/dev/null || true && \
    go install github.com/devploit/nomore403@latest 2>/dev/null || true && \
    go install github.com/haccer/subjack@latest 2>/dev/null || true && \
    go install github.com/hahwul/jaeles@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest 2>/dev/null || true && \
    go install github.com/gwen001/github-subdomains@latest 2>/dev/null || true && \
    go install github.com/hakluke/hakip2host@latest 2>/dev/null || true && \
    go install github.com/hakluke/haktrails@latest 2>/dev/null || true && \
    go install github.com/bp0lr/gauplus@latest 2>/dev/null || true && \
    go install github.com/d3mondev/puredns/v2@latest 2>/dev/null || true && \
    go install github.com/haccer/subover@latest 2>/dev/null || true && \
    go install github.com/anshumanbh/tko-subs@latest 2>/dev/null || true && \
    go install github.com/mhmdiaa/second-order@latest 2>/dev/null || true && \
    go install github.com/tomnomnom/kxss@latest 2>/dev/null || true && \
    go install github.com/praetorian-inc/gato@latest 2>/dev/null || true && \
    go install github.com/zricethezav/gitleaks/v8@latest 2>/dev/null || true && \
    go install github.com/liamg/gitjacker@latest 2>/dev/null || true && \
    go install github.com/anchore/xeol@latest 2>/dev/null || true && \
    go install github.com/sonatype-nexus-community/nancy@latest 2>/dev/null || true && \
    go install github.com/future-architect/vuls@latest 2>/dev/null || true && \
    go clean -cache -modcache && \
    rm -rf ~/go/pkg

# ── Cargo (Rust) tools ───────────────────────────────────────────────────────
RUN cargo install cargo-audit 2>/dev/null || true && \
    cargo install ripgen 2>/dev/null || true && \
    cargo install rusty-hog 2>/dev/null || true

USER root

# ── Promote builder binaries to system PATH ───────────────────────────────────
RUN find /home/builder/go/bin -maxdepth 1 -type f -exec cp {} /usr/local/bin/ \; 2>/dev/null || true && \
    find /home/builder/.cargo/bin -maxdepth 1 -type f -exec cp {} /usr/local/bin/ \; 2>/dev/null || true && \
    rm -rf /var/cache/pacman/ /tmp/pacman* \
           /home/builder/.cache/go-build \
           /home/builder/.cache/yay

# ── Ruby gems ────────────────────────────────────────────────────────────────
RUN gem install --no-document bundler-audit cfn_nag rubocop rubocop-ast \
        dawnscanner license_finder 2>/dev/null || true

# ── Bearer ───────────────────────────────────────────────────────────────────
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin

# ── Cherrybomb ───────────────────────────────────────────────────────────────
RUN CHERRY_URL=$(curl -s https://api.github.com/repos/blst-security/cherrybomb/releases/latest \
        | grep '"browser_download_url"' | grep -i 'linux' | grep -v '\.sha' | head -1 | cut -d'"' -f4) && \
    [ -n "$CHERRY_URL" ] && \
    curl -sLo /usr/local/bin/cherrybomb "$CHERRY_URL" && \
    chmod +x /usr/local/bin/cherrybomb || true

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
        pip install --break-system-packages --no-cache-dir "$pkg" 2>/dev/null \
            || echo "[skip] $pkg"; \
    done && \
    pip install --break-system-packages --no-cache-dir --no-deps apifuzzer 2>/dev/null || true

# apkid: try with --no-build-isolation so it uses the system libyara already installed
RUN pip install --break-system-packages --no-cache-dir --no-build-isolation apkid 2>/dev/null || \
    echo "[skip] apkid — yara-python-dex build failed"

# Tools not on PyPI — install from git source
RUN pip install --break-system-packages --no-cache-dir \
        git+https://github.com/Nefcore/CRLFsuite.git 2>/dev/null || true && \
    pip install --break-system-packages --no-cache-dir \
        git+https://github.com/codingo/VHostScan.git 2>/dev/null || true && \
    pip install --break-system-packages --no-cache-dir \
        git+https://github.com/AndroBugs/AndroBugs_Framework.git 2>/dev/null || true

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
    rm /tmp/tls-scanner.zip || true

# ── Source-only tools ─────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/swisskyrepo/SSRFmap /opt/SSRFmap && \
    pip install --break-system-packages --no-cache-dir -r /opt/SSRFmap/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/s0md3v/Oralyzer /opt/oralyzer 2>/dev/null || true && \
    pip install --break-system-packages --no-cache-dir -r /opt/oralyzer/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/vladko312/SSTImap /opt/SSTImap && \
    pip install --break-system-packages --no-cache-dir -r /opt/SSTImap/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/s0md3v/Corsy /opt/Corsy

RUN git clone --depth 1 https://github.com/mufeedvh/aemhacker /opt/aemhacker 2>/dev/null || true && \
    pip install --break-system-packages --no-cache-dir -r /opt/aemhacker/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/xnl-h4ck3r/xnLinkFinder /opt/xnLinkFinder && \
    pip install --break-system-packages --no-cache-dir -r /opt/xnLinkFinder/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/nahamsec/JSParser /opt/JSParser 2>/dev/null || true

RUN git clone --depth 1 https://github.com/1N3/BlackWidow /opt/blackwidow 2>/dev/null || true && \
    pip install --break-system-packages --no-cache-dir -r /opt/blackwidow/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/nikitastupin/csprecon /opt/csprecon 2>/dev/null || true && \
    pip install --break-system-packages --no-cache-dir -r /opt/csprecon/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/nccgroup/ScoutSuite /opt/ScoutSuite && \
    pip install --break-system-packages --no-cache-dir -r /opt/ScoutSuite/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/aquasecurity/cloudsploit /opt/cloudsploit && \
    cd /opt/cloudsploit && npm install --no-audit --no-fund 2>/dev/null || true && \
    printf '#!/bin/sh\nexec node /opt/cloudsploit/index.js "$@"\n' > /usr/local/bin/cloudsploit && \
    chmod +x /usr/local/bin/cloudsploit

RUN git clone --depth 1 https://github.com/michenriksen/gitrob /opt/gitrob && \
    cd /opt/gitrob && go build -o /usr/local/bin/gitrob . 2>/dev/null || true

RUN git clone --depth 1 https://github.com/RhinoSecurityLabs/cloudFox /opt/CloudFox && \
    cd /opt/CloudFox && go build -o /usr/local/bin/cloudfox . 2>/dev/null || true

RUN git clone --depth 1 https://github.com/s0md3v/Photon /opt/photon && \
    pip install --break-system-packages --no-cache-dir -r /opt/photon/requirements.txt 2>/dev/null || true && \
    printf '#!/bin/sh\nexec python3 /opt/photon/photon.py "$@"\n' > /usr/local/bin/photon && \
    chmod +x /usr/local/bin/photon

RUN git clone --depth 1 https://github.com/six2dez/reconftw /opt/reconftw && \
    chmod +x /opt/reconftw/reconftw.sh && \
    ln -sf /opt/reconftw/reconftw.sh /usr/local/bin/reconftw.sh

RUN git clone --depth 1 https://github.com/sa7mon/AWSBucketDump /opt/AWSBucketDump && \
    pip install --break-system-packages --no-cache-dir -r /opt/AWSBucketDump/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/maaaaz/androwarn /opt/androwarn && \
    pip install --break-system-packages --no-cache-dir -r /opt/androwarn/requirements.txt 2>/dev/null || true && \
    printf '#!/bin/sh\nexec python3 /opt/androwarn/androwarn.py "$@"\n' > /usr/local/bin/androwarn && \
    chmod +x /usr/local/bin/androwarn

# ── Wrapper scripts for source-only Python tools ──────────────────────────────
# Create /usr/local/bin/<name> shim only when the entry-point script exists.
RUN for spec in \
        "aemhacker:/opt/aemhacker/aem_hacker.py" \
        "blackwidow:/opt/blackwidow/blackwidow.py" \
        "oralyzer:/opt/oralyzer/oralyzer.py" \
        "csprecon:/opt/csprecon/csprecon.py"; do \
    name="${spec%%:*}"; path="${spec##*:}"; \
    [ -f "$path" ] && \
        printf '#!/bin/sh\nexec python3 %s "$@"\n' "$path" > "/usr/local/bin/$name" && \
        chmod +x "/usr/local/bin/$name" || true; \
done

# ── Joern (requires JVM) ─────────────────────────────────────────────────────
RUN JOERN_VER=$(curl -s https://api.github.com/repos/joernio/joern/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$JOERN_VER" ] && \
    curl -sL "https://github.com/joernio/joern/releases/download/${JOERN_VER}/joern-install.sh" \
         -o /tmp/joern-install.sh && \
    chmod +x /tmp/joern-install.sh && \
    /tmp/joern-install.sh --prefix /opt/joern 2>/dev/null && \
    ln -sf /opt/joern/joern-cli/joern /usr/local/bin/joern || true

# ── Infer (Facebook SAST) ────────────────────────────────────────────────────
RUN INFER_VER=$(curl -s https://api.github.com/repos/facebook/infer/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$INFER_VER" ] && \
    curl -sL "https://github.com/facebook/infer/releases/download/${INFER_VER}/infer-linux64-${INFER_VER}.tar.xz" \
         -o /tmp/infer.tar.xz && \
    tar -xf /tmp/infer.tar.xz -C /opt/ && \
    mv /opt/infer-linux64-${INFER_VER} /opt/infer && \
    ln -sf /opt/infer/bin/infer /usr/local/bin/infer && \
    rm /tmp/infer.tar.xz || true

# ── PMD (Java SAST) ──────────────────────────────────────────────────────────
RUN PMD_VER=$(curl -s https://api.github.com/repos/pmd/pmd/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | sed 's/pmd_releases\///') && \
    [ -n "$PMD_VER" ] && \
    curl -sL "https://github.com/pmd/pmd/releases/download/pmd_releases/${PMD_VER}/pmd-dist-${PMD_VER}-bin.zip" \
         -o /tmp/pmd.zip && \
    unzip -q /tmp/pmd.zip -d /opt/ && \
    mv /opt/pmd-bin-${PMD_VER} /opt/pmd && \
    ln -sf /opt/pmd/bin/pmd /usr/local/bin/pmd && \
    rm /tmp/pmd.zip || true

# ── SpotBugs (Java) ──────────────────────────────────────────────────────────
RUN SB_VER=$(curl -s https://api.github.com/repos/spotbugs/spotbugs/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$SB_VER" ] && \
    curl -sL "https://github.com/spotbugs/spotbugs/releases/download/${SB_VER}/spotbugs-${SB_VER}.tgz" \
         -o /tmp/spotbugs.tgz && \
    tar -xf /tmp/spotbugs.tgz -C /opt/ && \
    mv /opt/spotbugs-${SB_VER} /opt/spotbugs && \
    ln -sf /opt/spotbugs/bin/spotbugs /usr/local/bin/spotbugs && \
    rm /tmp/spotbugs.tgz || true

# ── CodeQL CLI ───────────────────────────────────────────────────────────────
RUN CQL_VER=$(curl -s https://api.github.com/repos/github/codeql-action/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$CQL_VER" ] && \
    curl -sL "https://github.com/github/codeql-action/releases/download/${CQL_VER}/codeql-bundle-linux64.tar.gz" \
         -o /tmp/codeql.tar.gz && \
    tar -xf /tmp/codeql.tar.gz -C /opt/ && \
    ln -sf /opt/codeql/codeql /usr/local/bin/codeql && \
    rm /tmp/codeql.tar.gz || true

# ── npm global tools ──────────────────────────────────────────────────────────
RUN npm install -g --no-audit --no-fund \
        retire eslint eslint-plugin-security @microsoft/devskim wappalyzer 2>/dev/null || true

# ── Threagile ────────────────────────────────────────────────────────────────
RUN THREAGILE_VER=$(curl -s https://api.github.com/repos/Threagile/threagile/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$THREAGILE_VER" ] && \
    curl -sL "https://github.com/Threagile/threagile/releases/download/${THREAGILE_VER}/threagile-linux-amd64" \
         -o /usr/local/bin/threagile && \
    chmod +x /usr/local/bin/threagile || true

# ── WitnessME ────────────────────────────────────────────────────────────────
RUN pip install --break-system-packages --no-cache-dir witnessme 2>/dev/null || true

# ── MVT (Mobile Verification Toolkit) ────────────────────────────────────────
RUN pip install --break-system-packages --no-cache-dir mvt 2>/dev/null || true

# ── uv ───────────────────────────────────────────────────────────────────────
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
