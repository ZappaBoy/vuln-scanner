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
        tplmap checksec jwt-tool gittools git-dumper h2csmuggler kubescape-bin bbot kube-hunter \
        dirsearch joomscan whatwaf medusa cppcheck clamav yara rkhunter chkrootkit binwalk spiderfoot \
        findomain massdns shuffledns syft dockle docker-bench kubeaudit kube-score kube-linter popeye-bin dive \
        zmap kxss ghauri knockpy assetfinder-bin gotator gauplus csprecon github-subdomains chaos-client \
        insider-bin weggli zizmor subover tko-subs gitjacker gato s3scanner \
        kics regula cfn-nag-gem retire nodejs-retire wappalyzer-cli jaeles-bin \
        apkid apkleaks androwarn quark-engine mvt-mobile androbugs qark && \
    yay -Scc --noconfirm

RUN go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install github.com/aquasecurity/kube-bench@latest && \
    ( go install github.com/trufflesecurity/jsluice/cmd/jsluice@latest 2>/dev/null || true ) && \
    go install github.com/devploit/nomore403@latest && \
    go install github.com/haccer/subjack@latest && \
    go install github.com/hahwul/jaeles@latest && \
    go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest && \
    go install github.com/gwen001/github-subdomains@latest && \
    go install github.com/hakluke/hakip2host@latest && \
    go install github.com/bp0lr/gauplus@latest && \
    go install github.com/d3mondev/puredns/v2@latest && \
    go install github.com/haccer/subover@latest && \
    go install github.com/anshumanbh/tko-subs@latest && \
    go install github.com/mhmdiaa/second-order@latest && \
    go install github.com/xiecat/gato@latest && \
    go install github.com/zricethezav/gitleaks/v8@latest && \
    go install github.com/liamg/gitjacker@latest && \
    go install github.com/anchore/xeol@latest 2>/dev/null || true && \
    go clean -cache -modcache && \
    rm -rf /home/builder/go/pkg

USER root

RUN find /home/builder/go/bin -maxdepth 1 -type f -exec cp {} /usr/local/bin/ \; && \
    rm -rf /var/cache/pacman/ /tmp/pacman* \
           /home/builder/.cache/go-build \
           /home/builder/.cache/yay \
           /home/builder/.cache/yay-bin

# Ruby gems
RUN gem install --no-document bundler-audit cfn-nag rubocop rubocop-ast dawn dawnscanner license_finder 2>/dev/null || true

# cargo tools
RUN command -v cargo >/dev/null 2>&1 && \
    cargo install cargo-audit rusty-hog ripgen 2>/dev/null || true

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
        humble \
        crlfuite \
        VHostScan \
        dnsgen \
        waymore \
        whispers \
        scoutsuite \
        roadrecon \
        s3scanner \
        awsbucketdump \
        license-finder \
        wappalyzer \
        xsrfprobe \
        cloudsploit \
        garak \
        netaddr \
        python-slugify && \
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

# Tools available only via git clone
RUN git clone --depth 1 https://github.com/swisskyrepo/SSRFmap /opt/SSRFmap && \
    pip install --break-system-packages --no-cache-dir -r /opt/SSRFmap/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/s0md3v/Oralyzer /opt/oralyzer && \
    pip install --break-system-packages --no-cache-dir -r /opt/oralyzer/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/vladko312/SSTImap /opt/SSTImap && \
    pip install --break-system-packages --no-cache-dir -r /opt/SSTImap/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/s0md3v/Corsy /opt/Corsy && \
    pip install --break-system-packages --no-cache-dir requests 2>/dev/null || true

RUN git clone --depth 1 https://github.com/mufeedvh/aemhacker /opt/aemhacker && \
    pip install --break-system-packages --no-cache-dir -r /opt/aemhacker/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/spyse-com/xnLinkFinder /opt/xnLinkFinder && \
    pip install --break-system-packages --no-cache-dir -r /opt/xnLinkFinder/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/RuntimeTerror418/JSParser /opt/JSParser 2>/dev/null || true

RUN git clone --depth 1 https://github.com/nicowillis/blackwidow /opt/blackwidow && \
    pip install --break-system-packages --no-cache-dir -r /opt/blackwidow/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/nikitastupin/csprecon /opt/csprecon && \
    pip install --break-system-packages --no-cache-dir -r /opt/csprecon/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/mksec/parameth /opt/parameth 2>/dev/null || true

RUN git clone --depth 1 https://github.com/sa7mon/S3Scanner /opt/S3Scanner && \
    pip install --break-system-packages --no-cache-dir -r /opt/S3Scanner/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/nccgroup/ScoutSuite /opt/ScoutSuite && \
    pip install --break-system-packages --no-cache-dir -r /opt/ScoutSuite/requirements.txt 2>/dev/null || true

RUN git clone --depth 1 https://github.com/RhinoSecurityLabs/CloudFox /opt/CloudFox 2>/dev/null || true && \
    command -v go && cd /opt/CloudFox && go build -o /usr/local/bin/cloudfox . 2>/dev/null || true

RUN git clone --depth 1 https://github.com/doyensec/cloudsploit /opt/cloudsploit && \
    cd /opt/cloudsploit && npm install 2>/dev/null || true && \
    printf '#!/bin/sh\nexec node /opt/cloudsploit/index.js "$@"\n' > /usr/local/bin/cloudsploit && chmod +x /usr/local/bin/cloudsploit

RUN git clone --depth 1 https://github.com/d1vious/gitrob /opt/gitrob && \
    cd /opt/gitrob && go build -o /usr/local/bin/gitrob . 2>/dev/null || true

RUN git clone --depth 1 https://github.com/woodruffw/zizmor /opt/zizmor && \
    command -v cargo && cd /opt/zizmor && cargo install --path . 2>/dev/null || true

RUN git clone --depth 1 https://github.com/s0md3v/Photon /opt/photon && \
    pip install --break-system-packages --no-cache-dir -r /opt/photon/requirements.txt 2>/dev/null || true && \
    printf '#!/bin/sh\nexec python3 /opt/photon/photon.py "$@"\n' > /usr/local/bin/photon && chmod +x /usr/local/bin/photon

# joern (requires JVM)
RUN JOERN_VER=$(curl -s https://api.github.com/repos/joernio/joern/releases/latest | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$JOERN_VER" ] && \
    curl -sL "https://github.com/joernio/joern/releases/download/${JOERN_VER}/joern-install.sh" -o /tmp/joern-install.sh && \
    chmod +x /tmp/joern-install.sh && /tmp/joern-install.sh --prefix /opt/joern --no-build 2>/dev/null && \
    ln -sf /opt/joern/bin/joern /usr/local/bin/joern || true

# infer (Facebook SAST)
RUN INFER_VER=$(curl -s https://api.github.com/repos/facebook/infer/releases/latest | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$INFER_VER" ] && \
    curl -sL "https://github.com/facebook/infer/releases/download/${INFER_VER}/infer-linux64-${INFER_VER}.tar.xz" -o /tmp/infer.tar.xz && \
    tar -xf /tmp/infer.tar.xz -C /opt/ && mv /opt/infer-linux64-${INFER_VER} /opt/infer && \
    ln -sf /opt/infer/bin/infer /usr/local/bin/infer && rm /tmp/infer.tar.xz || true

# PMD (Java SAST)
RUN PMD_VER=$(curl -s https://api.github.com/repos/pmd/pmd/releases/latest | grep '"tag_name"' | cut -d'"' -f4 | sed 's/pmd_releases\///') && \
    [ -n "$PMD_VER" ] && \
    curl -sL "https://github.com/pmd/pmd/releases/download/pmd_releases/${PMD_VER}/pmd-dist-${PMD_VER}-bin.zip" -o /tmp/pmd.zip && \
    unzip -q /tmp/pmd.zip -d /opt/ && mv /opt/pmd-bin-${PMD_VER} /opt/pmd && \
    ln -sf /opt/pmd/bin/pmd /usr/local/bin/pmd && rm /tmp/pmd.zip || true

# SpotBugs (Java)
RUN SB_VER=$(curl -s https://api.github.com/repos/spotbugs/spotbugs/releases/latest | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$SB_VER" ] && \
    curl -sL "https://github.com/spotbugs/spotbugs/releases/download/${SB_VER}/spotbugs-${SB_VER}.tgz" -o /tmp/spotbugs.tgz && \
    tar -xf /tmp/spotbugs.tgz -C /opt/ && mv /opt/spotbugs-${SB_VER} /opt/spotbugs && \
    ln -sf /opt/spotbugs/bin/spotbugs /usr/local/bin/spotbugs && rm /tmp/spotbugs.tgz || true

# CodeQL CLI
RUN CQL_VER=$(curl -s https://api.github.com/repos/github/codeql-action/releases/latest | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$CQL_VER" ] && \
    curl -sL "https://github.com/github/codeql-action/releases/download/${CQL_VER}/codeql-bundle-linux64.tar.gz" -o /tmp/codeql.tar.gz && \
    tar -xf /tmp/codeql.tar.gz -C /opt/ && \
    ln -sf /opt/codeql/codeql /usr/local/bin/codeql && rm /tmp/codeql.tar.gz || true

# DevSkim (npm)
RUN npm install -g @microsoft/devskim 2>/dev/null || true && \
    npm install -g retire eslint eslint-plugin-security 2>/dev/null || true

# Psalm + Progpilot (PHP)
RUN command -v composer >/dev/null 2>&1 && \
    composer global require vimeo/psalm getprogpilot/progpilot 2>/dev/null || true

# Reconftw
RUN git clone --depth 1 https://github.com/six2dez/reconftw /opt/reconftw && \
    chmod +x /opt/reconftw/reconftw.sh && \
    ln -sf /opt/reconftw/reconftw.sh /usr/local/bin/reconftw.sh || true

# Nancy (Go dependency auditor)
RUN go install github.com/sonatype-nexus-community/nancy@latest 2>/dev/null || true

# Threagile
RUN THREAGILE_VER=$(curl -s https://api.github.com/repos/Threagile/threagile/releases/latest | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$THREAGILE_VER" ] && \
    curl -sL "https://github.com/Threagile/threagile/releases/download/${THREAGILE_VER}/threagile-linux-amd64" -o /usr/local/bin/threagile && \
    chmod +x /usr/local/bin/threagile || true

# WitnessME
RUN pip install --break-system-packages --no-cache-dir witnessme 2>/dev/null || true

# Vuls (agentless vuln scanner)
RUN go install github.com/future-architect/vuls@latest 2>/dev/null || true

# MobSF (set up API wrapper — actual server runs separately)
RUN pip install --break-system-packages --no-cache-dir requests 2>/dev/null || true

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
