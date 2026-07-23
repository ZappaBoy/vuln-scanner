# syntax=docker/dockerfile:1.7

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 – Go tools
# Compiles all go-install tools in isolation so the Go SDK and module cache
# never appear in the final image.
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:latest AS go-builder

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/katana/cmd/katana@latest       && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest              && \
    go install github.com/aquasecurity/kube-bench@latest                  && \
    go install github.com/BishopFox/jsluice/cmd/jsluice@latest            && \
    go install github.com/devploit/nomore403@latest                       && \
    go install github.com/haccer/subjack@latest                           && \
    go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest  && \
    go install github.com/gwen001/github-subdomains@latest                && \
    go install github.com/hakluke/hakip2host@latest                       && \
    go install github.com/hakluke/haktrails@latest                        && \
    go install github.com/bp0lr/gauplus@latest                            && \
    go install github.com/d3mondev/puredns/v2@latest                      && \
    go install github.com/mhmdiaa/second-order@latest                     && \
    go install github.com/BishopFox/cloudfox@latest                       && \
    go install github.com/Josue87/gotator@latest                          && \
    go install github.com/Emoe/kxss@latest                                && \
    go install github.com/xeol-io/xeol/cmd/xeol@latest                   && \
    go install github.com/zricethezav/gitleaks/v8@latest                  && \
    go install github.com/sonatype-nexus-community/nancy@latest           && \
    go install github.com/threagile/threagile@latest

# KICS is built from source to get the binary plus its on-disk query/library assets.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    git clone --depth 1 https://github.com/Checkmarx/kics.git /kics && \
    cd /kics && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /kics/bin/kics ./cmd/console

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 – Rust tools
# Compiles Rust-based tools in isolation so the Rust toolchain and registry
# cache never appear in the final image.
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1-slim AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ cmake make pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install cargo-audit ripgen weggli

# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 – tool-builder
# Builds every "manually installed" tool (pip / gem / npm / DevSkim / GitHub
# release downloads / git-clone tools) on the blackarch base, but WITHOUT the
# ~200 pacman/yay security tools — those don't participate in building these and
# are installed directly in the final stage instead. The heavy build-only bits
# (dotnet-sdk, download tarballs, pip/npm build caches) live only here and are
# dropped when the final stage copies just the resulting artifacts.
#
# Everything is arranged so the final stage can grab it with a handful of copies:
#   /usr/local            → go/rust bins, downloaded binaries, wrappers, bearer,
#                           kics, DevSkim symlink, gem/npm/pip console scripts
#   /opt                  → git-clone tools + extracted archives (joern, pmd, …)
#   /usr/lib/python*/site-packages, /usr/lib/ruby/gems → pip/gem libraries
#   /root/.dotnet         → the DevSkim .NET tool
# ─────────────────────────────────────────────────────────────────────────────
FROM blackarchlinux/blackarch:latest AS tool-builder

# Build essentials + interpreters + the .NET SDK (needed only to install DevSkim).
RUN --mount=type=cache,target=/var/cache/pacman/pkg,sharing=locked \
    pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed \
    base-devel git curl unzip sudo \
    python python-pip ruby nodejs npm dotnet-sdk

# ── Ruby gems (scripts → /usr/local/bin, libs → /usr/lib/ruby/gems) ────────────
RUN gem install --no-document --no-user-install --bindir /usr/local/bin \
    bundler-audit cfn-nag dawnscanner license_finder rubocop rubocop-ast && \
    gem cleanup --silent && \
    rm -rf /root/.gem/ruby/*/cache /usr/lib/ruby/gems/*/cache

# ── Bearer ────────────────────────────────────────────────────────────────────
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# ── pip packages ──────────────────────────────────────────────────────────────
# Each tool is installed individually so a native-dep build failure is non-fatal.
# pip drops console scripts in /usr/bin; since Arch doesn't put /usr/local on
# sys.path we can't relocate the libraries, so instead we snapshot /usr/bin and
# move the newly-created scripts into /usr/local/bin, letting a single /usr/local
# copy capture every pip entrypoint in the final stage.
RUN --mount=type=cache,target=/root/.cache/pip \
    ls -1 /usr/bin | sort > /tmp/bin.before ; \
    for pkg in \
    CORScanner drheader gvm-tools pip-audit \
    dnsgen waymore whispers \
    scoutsuite roadrecon s3scanner \
    xsrfprobe garak \
    quark-engine apkleaks qark \
    netaddr python-slugify \
    subdominator gato-x codechecker autosubtakeover \
    xnLinkFinder requests_pkcs12 mvt \
    git+https://github.com/guelfoweb/knockpy.git \
    git+https://github.com/Nefcore/CRLFsuite.git \
    git+https://github.com/codingo/VHostScan.git ; do \
    pip install --break-system-packages "$pkg" ; \
    done ; \
    pip install --break-system-packages --no-deps apifuzzer ; \
    ls -1 /usr/bin | sort > /tmp/bin.after && \
    comm -13 /tmp/bin.before /tmp/bin.after | while read -r f; do \
    mv "/usr/bin/$f" /usr/local/bin/ 2>/dev/null || true ; \
    done && \
    rm -f /tmp/bin.before /tmp/bin.after

# ── npm global tools (prefix /usr/local so they land in the copied tree) ───────
RUN --mount=type=cache,target=/root/.npm \
    npm install -g --prefix /usr/local eslint yarn --no-audit --no-fund

# ── DevSkim (.NET global tool) ────────────────────────────────────────────────
# Installed with the SDK here; the final stage ships only the .NET runtime and
# copies /root/.dotnet, so the ~1 GB SDK never reaches the image.
RUN dotnet tool install --global Microsoft.CST.DevSkim.CLI && \
    ln -sf /root/.dotnet/tools/devskim /usr/local/bin/devskim

# ── Prebuilt binaries from GitHub releases (versions pinned; no API calls) ─────
RUN tarbin() { curl -sfL "$1" -o /tmp/dl.tgz && tar -xf /tmp/dl.tgz -C /usr/local/bin/ "$2" && rm -f /tmp/dl.tgz; }; \
    rawbin() { curl -sfL "$1" -o "/usr/local/bin/$2"; }; \
    tarbin "https://github.com/zegl/kube-score/releases/download/v1.20.0/kube-score_1.20.0_linux_amd64.tar.gz" kube-score && \
    tarbin "https://github.com/Shopify/kubeaudit/releases/download/v0.22.2/kubeaudit_0.22.2_linux_amd64.tar.gz" kubeaudit && \
    tarbin "https://github.com/insidersec/insider/releases/download/3.0.0/insider_3.0.0_linux_x86_64.tar.gz" insider && \
    tarbin "https://github.com/fugue/regula/releases/download/v3.2.1/regula_3.2.1_Linux_x86_64.tar.gz" regula && \
    rawbin "https://github.com/designsecurity/progpilot/releases/download/v1.3.0/progpilot_v1.3.0.phar" progpilot && \
    rawbin "https://github.com/blst-security/cherrybomb/releases/download/v1.0.0/cherrybomb_linux_gnu" cherrybomb && \
    rawbin "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.32.0/cyclonedx-linux-x64" cyclonedx && \
    chmod +x /usr/local/bin/kube-score /usr/local/bin/kubeaudit /usr/local/bin/insider \
             /usr/local/bin/regula /usr/local/bin/progpilot \
             /usr/local/bin/cherrybomb /usr/local/bin/cyclonedx

# KICS — binary + assets from the go-builder, wrapped to inject the asset paths.
COPY --from=go-builder /kics/bin/kics /usr/local/bin/kics-bin
COPY --from=go-builder /kics/assets /opt/kics/assets
RUN printf '#!/bin/sh\nexec /usr/local/bin/kics-bin "$@" --queries-path /opt/kics/assets/queries --libraries-path /opt/kics/assets/libraries\n' \
    > /usr/local/bin/kics && \
    chmod +x /usr/local/bin/kics

# rusty-hog — New Relic's suite of secret scanners (one binary per source type).
RUN RHVER=1.0.11 && \
    for hog in ankamali_hog berkshire_hog choctaw_hog duroc_hog \
               essex_hog gottingen_hog hante_hog; do \
        curl -sL "https://github.com/newrelic/rusty-hog/releases/download/v${RHVER}/rustyhogs-musl-${hog}-${RHVER}.zip" \
            -o "/tmp/${hog}.zip" && \
        unzip -q "/tmp/${hog}.zip" -d "/tmp/${hog}/" && \
        find "/tmp/${hog}" -type f -name "${hog}" -exec install -m755 {} /usr/local/bin/ \; && \
        rm -rf "/tmp/${hog}.zip" "/tmp/${hog}/" ; \
    done

# infer (Meta static analyser)
RUN INFER_VER=$(curl -s https://api.github.com/repos/facebook/infer/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$INFER_VER" ] && \
    curl -sL "https://github.com/facebook/infer/releases/download/${INFER_VER}/infer-linux-x86_64-${INFER_VER}.tar.xz" \
    -o /tmp/infer.tar.xz && \
    tar -xf /tmp/infer.tar.xz -C /opt/ && \
    mv /opt/infer-linux-x86_64-${INFER_VER} /opt/infer && \
    ln -sf /opt/infer/bin/infer /usr/local/bin/infer && \
    rm /tmp/infer.tar.xz

# ── dnsreaper ─────────────────────────────────────────────────────────────────
RUN --mount=type=cache,target=/root/.cache/pip \
    git clone --depth 1 https://github.com/punk-security/dnsReaper /opt/dnsreaper && \
    pip install --break-system-packages -r /opt/dnsreaper/requirements.txt && \
    python3 -c "import glob; [open(p,'w').write(open(p).read().replace('from pkg_resources import get_distribution','from importlib.metadata import version as _iv\nget_distribution=lambda n:type(chr(95)+\"D\",(),{\"version\":_iv(n)})()')) for p in glob.glob('/usr/lib/python*/site-packages/google/cloud/dns/__init__.py')]" && \
    printf '#!/bin/sh\nexec python3 /opt/dnsreaper/main.py "$@"\n' > /usr/local/bin/dnsreaper && \
    chmod +x /usr/local/bin/dnsreaper && \
    rm -rf /opt/dnsreaper/.git

# ── TLS-Attacker ──────────────────────────────────────────────────────────────
RUN TLS_URL=$(curl -s https://api.github.com/repos/tls-attacker/TLS-Scanner/releases/latest \
    | grep '"browser_download_url"' | grep '\.zip"' | head -1 | cut -d'"' -f4) && \
    [ -n "$TLS_URL" ] && \
    curl -sL "$TLS_URL" -o /tmp/tls-scanner.zip && \
    unzip -q /tmp/tls-scanner.zip -d /opt/tls-scanner && \
    JAR=$(find /opt/tls-scanner -name "*.jar" | head -1) && \
    printf "#!/bin/sh\nexec java -jar %s \"\$@\"\n" "$JAR" > /usr/local/bin/TLS-Scanner && \
    chmod +x /usr/local/bin/TLS-Scanner && \
    rm /tmp/tls-scanner.zip

# ── Source-only tools (git clone + optional requirements.txt) ─────────────────
RUN --mount=type=cache,target=/root/.cache/pip \
    clone_reqs() { git clone --depth 1 "$1" "$2" && \
        if [ -f "$2/requirements.txt" ]; then pip install --break-system-packages -r "$2/requirements.txt"; fi && \
        rm -rf "$2/.git"; }; \
    mkwrap() { printf '#!/bin/sh\nexec python3 %s "$@"\n' "$2" > "/usr/local/bin/$1" && chmod +x "/usr/local/bin/$1"; }; \
    clone_reqs https://github.com/swisskyrepo/SSRFmap       /opt/SSRFmap       && \
    clone_reqs https://github.com/vladko312/SSTImap         /opt/SSTImap       && \
    clone_reqs https://github.com/s0md3v/Corsy              /opt/Corsy         && \
    clone_reqs https://github.com/nahamsec/JSParser         /opt/JSParser      && \
    clone_reqs https://github.com/1N3/BlackWidow            /opt/blackwidow    && \
    clone_reqs https://github.com/nccgroup/ScoutSuite       /opt/ScoutSuite    && \
    clone_reqs https://github.com/jordanpotti/AWSBucketDump /opt/AWSBucketDump && \
    clone_reqs https://github.com/rfc-st/humble             /opt/humble    && mkwrap humble    /opt/humble/humble.py       && \
    clone_reqs https://github.com/s0md3v/Photon             /opt/photon    && mkwrap photon    /opt/photon/photon.py       && \
    clone_reqs https://github.com/maaaaz/androwarn          /opt/androwarn && mkwrap androwarn /opt/androwarn/androwarn.py

# csprecon — pip install if it has a package, else fall back to a module shim.
RUN --mount=type=cache,target=/root/.cache/pip \
    git clone --depth 1 https://github.com/nikitastupin/csprecon /opt/csprecon && \
    pip install --break-system-packages /opt/csprecon  || \
    pip install --break-system-packages -r /opt/csprecon/requirements.txt  && \
    which csprecon  || \
    printf '#!/bin/sh\nexec python3 -m csprecon "$@"\n' > /usr/local/bin/csprecon && chmod +x /usr/local/bin/csprecon && \
    rm -rf /opt/csprecon/.git

# cloudsploit — Node app; wrapper runs its entrypoint.
RUN --mount=type=cache,target=/root/.npm \
    git clone --depth 1 https://github.com/aquasecurity/cloudsploit /opt/cloudsploit && \
    cd /opt/cloudsploit && npm install --no-audit --no-fund && \
    printf '#!/bin/sh\nexec node /opt/cloudsploit/index.js "$@"\n' > /usr/local/bin/cloudsploit && \
    chmod +x /usr/local/bin/cloudsploit && \
    rm -rf /opt/cloudsploit/.git

# reconftw + docker-bench-security — shell-script tools exposed via symlink.
RUN git clone --depth 1 https://github.com/six2dez/reconftw /opt/reconftw && \
    chmod +x /opt/reconftw/reconftw.sh && \
    ln -sf /opt/reconftw/reconftw.sh /usr/local/bin/reconftw.sh && \
    rm -rf /opt/reconftw/.git && \
    git clone --depth 1 https://github.com/docker/docker-bench-security /opt/docker-bench-security && \
    chmod +x /opt/docker-bench-security/docker-bench-security.sh && \
    ln -sf /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security && \
    rm -rf /opt/docker-bench-security/.git

# ── Wrapper scripts for source-only Python tools ──────────────────────────────
RUN for spec in \
    "aemhacker:/opt/aemhacker/aem_hacker.py" \
    "blackwidow:/opt/blackwidow/blackwidow.py" \
    "oralyzer:/opt/oralyzer/oralyzer.py"; do \
    name="${spec%%:*}"; path="${spec##*:}"; \
    printf '#!/bin/sh\nexec python3 %s "$@"\n' "$path" > "/usr/local/bin/$name" && \
    chmod +x "/usr/local/bin/$name"; \
    done

# cloudscraper — library only on PyPI; wrap it as a minimal CLI.
RUN printf '#!/usr/bin/env python3\nimport sys, json, argparse\nimport cloudscraper\np = argparse.ArgumentParser()\np.add_argument("--keyword")\np.add_argument("--output")\na = p.parse_args()\ns = cloudscraper.create_scraper()\ntry:\n    r = s.get(a.keyword)\n    out = {"url": a.keyword, "status": r.status_code, "body": r.text[:4096]}\n    print(json.dumps(out) if a.output == "json" else r.text)\nexcept Exception as e:\n    print(json.dumps({"error": str(e)}), file=sys.stderr)\n    sys.exit(1)\n' > /usr/local/bin/cloudscraper && \
    chmod +x /usr/local/bin/cloudscraper

# ── Joern (JVM), PMD, SpotBugs, CodeQL — extracted under /opt, symlinked ───────
RUN JOERN_VER=$(curl -s https://api.github.com/repos/joernio/joern/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$JOERN_VER" ] && \
    curl -sL "https://github.com/joernio/joern/releases/download/${JOERN_VER}/joern-install.sh" \
    -o /tmp/joern-install.sh && \
    chmod +x /tmp/joern-install.sh && \
    /tmp/joern-install.sh --prefix /opt/joern && \
    ln -sf /opt/joern/joern-cli/joern /usr/local/bin/joern && \
    rm -f /tmp/joern-install.sh

RUN PMD_VER=$(curl -s https://api.github.com/repos/pmd/pmd/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4 | sed 's/pmd_releases\///') && \
    [ -n "$PMD_VER" ] && \
    curl -sL "https://github.com/pmd/pmd/releases/download/pmd_releases/${PMD_VER}/pmd-dist-${PMD_VER}-bin.zip" \
    -o /tmp/pmd.zip && \
    unzip -q /tmp/pmd.zip -d /opt/ && \
    mv /opt/pmd-bin-${PMD_VER} /opt/pmd && \
    ln -sf /opt/pmd/bin/pmd /usr/local/bin/pmd && \
    rm /tmp/pmd.zip

RUN SB_VER=$(curl -s https://api.github.com/repos/spotbugs/spotbugs/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$SB_VER" ] && \
    curl -sL "https://github.com/spotbugs/spotbugs/releases/download/${SB_VER}/spotbugs-${SB_VER}.tgz" \
    -o /tmp/spotbugs.tgz && \
    tar -xf /tmp/spotbugs.tgz -C /opt/ && \
    mv /opt/spotbugs-${SB_VER} /opt/spotbugs && \
    ln -sf /opt/spotbugs/bin/spotbugs /usr/local/bin/spotbugs && \
    rm /tmp/spotbugs.tgz

RUN CQL_VER=$(curl -s https://api.github.com/repos/github/codeql-action/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4) && \
    [ -n "$CQL_VER" ] && \
    curl -sL "https://github.com/github/codeql-action/releases/download/${CQL_VER}/codeql-bundle-linux64.tar.gz" \
    -o /tmp/codeql.tar.gz && \
    tar -xf /tmp/codeql.tar.gz -C /opt/ && \
    ln -sf /opt/codeql/codeql /usr/local/bin/codeql && \
    rm /tmp/codeql.tar.gz

# ─────────────────────────────────────────────────────────────────────────────
# Stage 4 – Final scanner image
# Installs the pacman/yay security tools (so their shared libs + data are present
# and correct) and copies the pre-built binaries/assets/libraries from the
# builder stages. Ships the .NET runtime instead of the SDK.
# ─────────────────────────────────────────────────────────────────────────────
FROM blackarchlinux/blackarch:latest

# ── Go / Rust tool binaries ───────────────────────────────────────────────────
COPY --from=go-builder /go/bin/ /usr/local/bin/
COPY --from=rust-builder \
    /usr/local/cargo/bin/cargo-audit \
    /usr/local/cargo/bin/ripgen \
    /usr/local/cargo/bin/weggli \
    /usr/local/bin/

# ── Base system + interpreters + yay ──────────────────────────────────────────
# dotnet-runtime (not -sdk): DevSkim is copied pre-installed and only needs the
# runtime. base-devel is kept — infer/codechecker shell out to gcc/make at scan
# time, and yay needs it to build AUR packages.
RUN --mount=type=cache,target=/var/cache/pacman/pkg,sharing=locked \
    pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed \
    jdk-openjdk git base-devel sudo python python-pip unzip curl \
    nodejs npm ruby php openscap dotnet-runtime && \
    useradd -m -G wheel builder && \
    echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers && \
    git clone https://aur.archlinux.org/yay.git /tmp/yay && \
    chown -R builder:builder /tmp/yay && \
    su builder -c 'cd /tmp/yay && makepkg -si --noconfirm' && \
    rm -rf /tmp/yay

USER builder

# ── BlackArch / AUR security tools ────────────────────────────────────────────
RUN --mount=type=cache,target=/home/builder/.cache,uid=1000,gid=1000,sharing=locked \
    --mount=type=cache,target=/var/cache/pacman/pkg,sharing=locked \
    yay -S --noconfirm --needed \
    alterx \
    amass \
    arachni \
    arjun \
    assetfinder \
    bandit \
    bbot \
    binwalk \
    blackarch/androbugs \
    blackarch/apkid \
    blackarch/brakeman \
    blackarch/dawnscanner \
    blackarch/gitrob \
    blackarch/horusec \
    blackarch/jaeles  \
    blackarch/secretfinder \
    blackarch/theharvester \
    blackarch/vuls \
    blackarch/whispers \
    brakeman \
    cariddi \
    checkov \
    checksec \
    chkrootkit \
    clamav \
    cmsmap  \
    commix \
    cppcheck \
    crackmapexec \
    crlfuzz \
    dalfox \
    dependency-check \
    detect-secrets \
    dirsearch \
    dnsrecon \
    dnsx \
    dockle-bin \
    enum4linux-ng \
    extra/dive \
    extra/kube-linter \
    extra/psalm \
    extra/rubocop \
    feroxbuster \
    ffuf \
    fierce \
    findomain \
    flawfinder \
    gau \
    ghauri \
    git-dumper \
    gitjacker  \
    gitleaks \
    gittools \
    gobuster \
    govulncheck \
    gowitness \
    graphql-cop \
    grype \
    h2csmuggler \
    hadolint-bin \
    hakrawler \
    httprobe \
    httpx \
    hydra \
    joomscan \
    jwt-tool \
    kiterunner \
    kube-hunter \
    kubescape-bin \
    linkfinder \
    lynis \
    masscan \
    massdns \
    medusa \
    naabu \
    netdiscover \
    nikto \
    nmap \
    noseyparker \
    nosqlmap \
    nuclei \
    openvas \
    osv-scanner \
    parameth  \
    paramspider \
    popeye-bin \
    prowler \
    puredns \
    python-jsbeautifier \
    python-requests \
    python-witnessme  \
    restler-fuzzer \
    retire \
    rkhunter \
    rustscan \
    s3scanner  \
    second-order \
    secretfinder \
    semgrep \
    shuffledns \
    smbmap \
    smuggler \
    spiderfoot \
    sqlmap \
    ssh-audit \
    sslscan \
    sslyze \
    subfinder \
    subjack \
    subover \
    subzy \
    syft  \
    terrascan-bin \
    testssl.sh \
    tfsec \
    theharvester \
    tlsx \
    tplmap \
    trivy \
    trufflehog \
    wafw00f \
    wapiti \
    wappalyzer-next-git \
    waybackurls \
    wfuzz \
    whatwaf \
    whatweb \
    wpscan \
    xsstrike \
    yara \
    zaproxy \
    zizmor  \
    zmap

USER root

# ── Clean up builder home ─────────────────────────────────────────────────────
RUN rm -rf /home/builder /var/cache/pacman/ /tmp/pacman*

# ── Copy the "manually installed" tools from the builder stage ────────────────
# A bind mount exposes the builder's filesystem read-only; cp -a merges the tool
# trees into the final image without pulling in the build toolchain, download
# tarballs, or the .NET SDK. cp -a only overwrites same-named files, so the
# pacman-provided python/ruby packages installed above are preserved and the
# pip/gem additions are layered on top. Python site-packages / ruby gem dirs are
# version-globbed so they track whatever the base image ships.
RUN --mount=type=bind,from=tool-builder,source=/,target=/mnt \
    cp -a /mnt/opt/. /opt/ && \
    cp -a /mnt/usr/local/. /usr/local/ && \
    cp -a /mnt/root/.dotnet /root/ && \
    cp -a /mnt/usr/lib/python3*/site-packages/. /usr/lib/python3*/site-packages/ && \
    cp -a /mnt/usr/lib/ruby/gems/. /usr/lib/ruby/gems/

# ── Wrappers that depend on pacman-installed tool files ───────────────────────
# SecretFinder + spiderfoot ship their CLI as a script under /usr/share|/usr/lib;
# expose each at the binary name the scanner expects.
RUN SF=$(find /usr/share /usr/lib -name "SecretFinder.py" 2>/dev/null | head -1) && \
    [ -n "$SF" ] && \
    printf '#!/bin/sh\nexec python3 %s "$@"\n' "$SF" > /usr/local/bin/SecretFinder && \
    chmod +x /usr/local/bin/SecretFinder ; \
    SFP=$(find /usr/share/spiderfoot /usr/lib/spiderfoot -name "sf.py" 2>/dev/null | head -1) && \
    [ -n "$SFP" ] && \
    printf '#!/bin/sh\nexec python3 %s "$@"\n' "$SFP" > /usr/local/bin/sf && \
    chmod +x /usr/local/bin/sf ; \
    command -v theHarvester >/dev/null 2>&1 || \
    { TH=$(find /usr/share /usr/lib -name "theHarvester.py" 2>/dev/null | head -1) && \
      [ -n "$TH" ] && \
      printf '#!/bin/sh\nexec python3 %s "$@"\n' "$TH" > /usr/local/bin/theHarvester && \
      chmod +x /usr/local/bin/theHarvester ; }

# ── uv ────────────────────────────────────────────────────────────────────────
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    ln -sf /root/.local/bin/uv /usr/local/bin/uv

# ── Final image cleanup ───────────────────────────────────────────────────────
RUN find /opt -maxdepth 2 -name ".git" -type d -exec rm -rf {} + 2>/dev/null ; \
    find /usr /usr/local -path "*/__pycache__" -type d -exec rm -rf {} + 2>/dev/null ; \
    find /usr /usr/local \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null ; \
    rm -rf /usr/share/man /usr/share/doc /usr/share/gtk-doc /usr/share/info \
    /root/.cache /root/.npm /root/.local/share/gem \
    /tmp/* /var/tmp/* || true

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
