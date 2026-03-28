FROM kalilinux/kali-rolling:latest

LABEL maintainer="openclaw-red-blue-team"
LABEL description="OpenClaw red team attack tooling — nmap, gobuster, sqlmap, pwntools, curl, python3"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ── Core attack toolchain ─────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        gobuster \
        sqlmap \
        curl \
        wget \
        netcat-openbsd \
        hydra \
        nikto \
        python3 \
        python3-pip \
        python3-venv \
        git \
        jq \
        procps \
        net-tools \
        iproute2 \
        iputils-ping \
        ca-certificates \
        mysql-client \
    && rm -rf /var/lib/apt/lists/*

# ── Python security libraries ─────────────────────────────────────────────────
RUN pip3 install --no-cache-dir \
        pwntools \
        requests \
        beautifulsoup4

# ── Wordlists ─────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends wordlists \
    && rm -rf /var/lib/apt/lists/* || true

# Ensure dirb wordlist exists (fallback if package unavailable)
RUN mkdir -p /usr/share/wordlists/dirb && \
    if [ ! -f /usr/share/wordlists/dirb/common.txt ]; then \
        printf '/admin\n/login\n/api\n/api/v1\n/backup\n/config\n/debug\n/health\n/metrics\n/setup\n/test\n' \
            > /usr/share/wordlists/dirb/common.txt; \
    fi

# Copy our custom API-focused wordlist into the image
COPY sandbox-images/openclaw-api-wordlist.txt /usr/share/wordlists/openclaw-api.txt

# ── Validate key tools are on PATH ───────────────────────────────────────────
RUN nmap --version && gobuster version && sqlmap --version

WORKDIR /workspace
CMD ["/bin/bash"]
