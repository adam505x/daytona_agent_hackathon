FROM python:3.11-slim

LABEL maintainer="openclaw-red-blue-team"
LABEL description="Harbinger Inventory API — intentionally vulnerable Flask target with forensic logging"

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Forensic / audit tooling
        auditd \
        audispd-plugins \
        procps \
        iproute2 \
        net-tools \
        lsof \
        curl \
        # Needed by process watcher
        cron \
    && rm -rf /var/lib/apt/lists/*

# ── Python app ────────────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the vulnerable Flask app
COPY app.py .

# Create the reports directory the app writes to
RUN mkdir -p /app/reports /var/log

# ── auditd rules (syscall traces) ────────────────────────────────────────────
COPY audit.rules /etc/audit/rules.d/openclaw.rules

# ── Process watcher (dumps ps/ss/lsof every 5s to /var/log/procs.log) ────────
COPY process_watcher.sh /usr/local/bin/process_watcher.sh
RUN chmod +x /usr/local/bin/process_watcher.sh

# ── Entrypoint starts everything ──────────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
