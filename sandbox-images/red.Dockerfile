FROM kalilinux/kali-rolling:latest

LABEL maintainer="openclaw-red-blue-team"
LABEL description="OpenClaw red team attack tooling image for Daytona sandboxes"

# ── Non-interactive installs ───────────────────────────────────────────────────
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ── Core toolchain ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Recon
        nmap \
        # Web path discovery
        gobuster \
        # SQL injection
        sqlmap \
        # Network utilities
        curl \
        wget \
        netcat-openbsd \
        socat \
        # Brute force
        hydra \
        # DNS / HTTP
        dnsutils \
        nikto \
        # Python ecosystem
        python3 \
        python3-pip \
        python3-venv \
        # System tools
        git \
        jq \
        procps \
        net-tools \
        iproute2 \
        iputils-ping \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Python security libraries ─────────────────────────────────────────────────
RUN pip3 install --no-cache-dir \
        pwntools \
        requests \
        beautifulsoup4 \
        lxml \
        paramiko \
        impacket \
        scapy

# ── Wordlists ─────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        wordlists \
        seclists \
    && rm -rf /var/lib/apt/lists/* || true

# Ensure common wordlists are available regardless of package availability
RUN mkdir -p /usr/share/wordlists && \
    if [ ! -f /usr/share/wordlists/rockyou.txt ]; then \
        # Minimal password list for lab use if rockyou not packaged
        printf 'admin\npassword\n123456\nroot\ntoor\ndvwa\nletmein\nqwerty\n' \
            > /usr/share/wordlists/rockyou.txt; \
    fi && \
    if [ ! -d /usr/share/wordlists/dirb ]; then \
        mkdir -p /usr/share/wordlists/dirb && \
        printf '/admin\n/login\n/setup\n/config\n/phpmyadmin\n/upload\n/uploads\n/images\n/backup\n/test\n/dvwa\n/vulnerabilities\n/security\n/.git\n/.env\n/api\n/admin.php\n/login.php\n/setup.php\n/config.php\n/index.php\n/register.php\n/user.php\n' \
            > /usr/share/wordlists/dirb/common.txt; \
    fi

# ── gobuster pre-check ────────────────────────────────────────────────────────
RUN gobuster version

# ── nmap NSE scripts update ───────────────────────────────────────────────────
RUN nmap --script-updatedb 2>/dev/null || true

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR /workspace

# ── Default shell ─────────────────────────────────────────────────────────────
CMD ["/bin/bash"]
