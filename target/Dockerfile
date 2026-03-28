FROM vulnerables/web-dvwa:latest

LABEL maintainer="openclaw-red-blue-team"
LABEL description="DVWA target with verbose logging, auditd, and process monitoring"

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        auditd \
        audispd-plugins \
        procps \
        iproute2 \
        curl \
        net-tools \
        lsof \
        cron \
    && rm -rf /var/lib/apt/lists/*

# ── Apache verbose / forensic logging ─────────────────────────────────────────
# Enable mod_log_forensic for full request/response logging
RUN a2enmod log_forensic || true

# Replace default access log with combined + forensic format
RUN cat > /etc/apache2/conf-available/verbose-logging.conf <<'EOF'
# Log every request with full headers and timing
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D %{forensic-id}n" combined_verbose
LogFormat "%{forensic-id}n %t %h \"%r\"" forensic_format

# Override the default vhost log
CustomLog /var/log/apache2/access_verbose.log combined_verbose
ErrorLog  /var/log/apache2/error_verbose.log
LogLevel  debug

# Forensic log (full request dump before and after processing)
ForensicLog /var/log/apache2/forensic.log
EOF

RUN a2enconf verbose-logging || true

# Keep a symlink so consumers can tail a single path
RUN ln -sf /var/log/apache2/access_verbose.log /var/log/access.log

# ── PHP error logging ──────────────────────────────────────────────────────────
RUN sed -i \
        -e 's/display_errors = Off/display_errors = On/' \
        -e 's/log_errors = Off/log_errors = On/' \
        -e 's|;error_log = php_errors.log|error_log = /var/log/php_errors.log|' \
        /etc/php/*/apache2/php.ini 2>/dev/null || \
    find /etc/php -name php.ini -exec sed -i \
        -e 's/display_errors = Off/display_errors = On/' \
        -e 's/log_errors = Off/log_errors = On/' \
        -e 's|;error_log = php_errors.log|error_log = /var/log/php_errors.log|' {} \;

# ── auditd rules ──────────────────────────────────────────────────────────────
COPY audit.rules /etc/audit/rules.d/openclaw.rules

# ── Process watcher script ────────────────────────────────────────────────────
COPY process_watcher.sh /usr/local/bin/process_watcher.sh
RUN chmod +x /usr/local/bin/process_watcher.sh

# ── Entrypoint wrapper ────────────────────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
