#!/usr/bin/env bash
# process_watcher.sh — dumps running processes every 5 seconds to /var/log/procs.log
# Includes full command lines, open files, and network connections for forensic analysis.

LOG=/var/log/procs.log
INTERVAL=5

mkdir -p "$(dirname "$LOG")"
: > "$LOG"  # truncate on start

log() {
    echo "$@" >> "$LOG"
}

while true; do
    TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    log "=== SNAPSHOT ${TIMESTAMP} ==="

    # Full process list with PID, PPID, user, CPU, MEM, command
    log "--- ps auxf ---"
    ps auxf >> "$LOG" 2>/dev/null

    # Open network connections (listeners + established)
    log "--- ss -tunap ---"
    ss -tunap >> "$LOG" 2>/dev/null

    # Open files for apache and php processes
    log "--- lsof apache/php ---"
    lsof -c apache2 -c php 2>/dev/null | head -100 >> "$LOG"

    # /proc entries for any process whose cmd contains "sh" or "python" or "perl"
    # (webshell indicators)
    log "--- suspicious proc cmdlines ---"
    for pid in /proc/[0-9]*/cmdline; do
        cmd=$(tr '\0' ' ' < "$pid" 2>/dev/null)
        if echo "$cmd" | grep -qE '(bash|sh |python|perl|nc |ncat|socat)'; then
            echo "PID $(basename $(dirname $pid)): $cmd" >> "$LOG"
        fi
    done

    log ""
    sleep "$INTERVAL"
done
