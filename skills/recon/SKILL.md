---
name: recon
description: Run nmap port scan and gobuster directory brute-force inside a Daytona sandbox against a target IP. Returns structured JSON of open ports, service versions, and discovered HTTP paths.
version: 1.0.0
metadata:
  openclaw:
    requires:
      env:
        - DAYTONA_API_KEY
      bins:
        - python3
    primaryEnv: DAYTONA_API_KEY
    emoji: "🔍"
---

# Skill: recon

Use this skill to enumerate a target after it has been provisioned.
This skill is **non-destructive** — it only reads, never writes to the target.

## When to invoke

- You have a running target sandbox and know its IP
- You need to discover what ports are open and what paths exist before exploiting
- You want to populate the finding queue for the exploit skill

## How to invoke

```bash
python3 orchestrator/red_team.py --recon-only \
  --sandbox-id "<recon-sandbox-id>" \
  --target-ip "<target-ip>"
```

Or call from within a Python orchestrator:

```python
from orchestrator.red_team import run_recon
findings = await run_recon(sandbox_id="sb-xyz", target_ip="10.88.0.5")
# findings["ports"]  -> list of {port, service, version}
# findings["paths"]  -> list of {path, status, size, port}
```

## What it returns (structured JSON)

```json
{
  "target": "10.88.0.5",
  "ports": [
    { "port": 5000, "protocol": "tcp", "state": "open", "service": "http", "version": "Werkzeug/3.0" }
  ],
  "paths": [
    { "path": "/api/inventory", "status": 200, "size": 312, "port": 5000 },
    { "path": "/api/report",    "status": 200, "size": 88,  "port": 5000 },
    { "path": "/api/diagnostics","status":405,  "size": 0,   "port": 5000 }
  ]
}
```

## Severity heuristics (auto-assigned to feed exploit triage)

| Signal | Assigned severity |
|--------|-------------------|
| Path ends in known query-param pattern (`?query=`, `?id=`, `?name=`) | high |
| HTTP 200 path contains `report`, `file`, `download` | high |
| HTTP 200 path contains `diag`, `ping`, `exec`, `check` | critical |
| Open database port (3306, 5432, 27017) | critical |
| Any open port other than 80/443/5000 | medium |

## Wordlist location

`/usr/share/wordlists/dirb/common.txt` is baked into `openclaw/red:latest`.
gobuster also runs a short custom list of API-style paths:
`/api/`, `/api/v1/`, `/api/inventory`, `/api/report`, `/api/diagnostics`,
`/api/admin`, `/api/auth/login`, `/health`, `/debug`, `/metrics`.

## Notes

- nmap runs full port scan (`-p 1-65535`) with service version detection (`-sV -sC`)
- gobuster runs against every port where nmap reports `http` or `http-alt`
- Both tools have a 120s timeout per invocation
- This skill does NOT send exploit payloads — it is safe to run against staging
