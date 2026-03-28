#!/usr/bin/env bash
# entrypoint.sh — starts DVWA services plus forensic monitoring daemons

set -e

echo "[entrypoint] Starting auditd..."
service auditd start || auditd -b 2>/dev/null || echo "[warn] auditd unavailable (needs --privileged)"

echo "[entrypoint] Starting process watcher..."
/usr/local/bin/process_watcher.sh &
WATCHER_PID=$!
echo "[entrypoint] Process watcher PID: $WATCHER_PID"

echo "[entrypoint] Starting MySQL..."
service mysql start

echo "[entrypoint] Starting Apache..."
source /etc/apache2/envvars
apache2 -D FOREGROUND &
APACHE_PID=$!

echo "[entrypoint] DVWA target ready. Logging to /var/log/"
echo "[entrypoint]   access log : /var/log/apache2/access_verbose.log"
echo "[entrypoint]   error log  : /var/log/apache2/error_verbose.log"
echo "[entrypoint]   forensic   : /var/log/apache2/forensic.log"
echo "[entrypoint]   procs      : /var/log/procs.log"
echo "[entrypoint]   audit      : journalctl -k -t audit"

# Wait for any child to exit; restart Apache if it crashes
wait $APACHE_PID
