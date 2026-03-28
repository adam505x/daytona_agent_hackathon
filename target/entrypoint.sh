#!/usr/bin/env bash
# entrypoint.sh — starts Flask app + forensic monitoring daemons

set -e

echo "[entrypoint] Starting auditd (requires --privileged or SYS_PTRACE)..."
service auditd start 2>/dev/null || auditd -b 2>/dev/null || echo "[warn] auditd unavailable"

echo "[entrypoint] Starting process watcher (dumps to /var/log/procs.log every 5s)..."
/usr/local/bin/process_watcher.sh &
echo "[entrypoint] Process watcher PID: $!"

echo "[entrypoint] Starting Harbinger Inventory API on :5000..."
exec python3 /app/app.py
