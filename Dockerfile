FROM blackarchlinux/blackarch:latest

RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed \
        nmap \
        nikto \
        nuclei \
        testssl.sh \
        python \
        python-pip \
        uv \
        wapiti \
        wpscan \
        ssh-audit \
        gitleaks \
        amass \
        zaproxy \
        trivy \
        sslyze && \
    pacman -Scc --noconfirm

WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --no-dev --no-install-project

COPY . .
RUN uv sync --no-dev

ENTRYPOINT ["uv", "run", "vuln-scanner"]
