---
name: daytona_spawn
description: Provision an isolated Daytona sandbox via the Daytona Python SDK, wait for readiness, and return the sandbox ID and internal IP address.
version: 1.0.0
metadata:
  openclaw:
    requires:
      env:
        - DAYTONA_API_KEY
      bins:
        - python3
    primaryEnv: DAYTONA_API_KEY
    emoji: "🐉"
    homepage: https://daytona.io
---

# Skill: daytona-spawn

Use this skill whenever you need to create a new isolated Daytona sandbox.
All red team attack sandboxes and the target sandbox are provisioned this way.

## When to invoke

- User asks to start the target environment
- You need a fresh sandbox to run a recon or exploit tool
- You are fanning out parallel exploit workers

## How to invoke

Run the spawn helper directly:

```bash
python3 orchestrator/red_team.py --spawn-only \
  --image "<docker-image>" \
  --label "<human-readable-label>"
```

Or call from within a Python orchestrator:

```python
from orchestrator.red_team import create_sandbox
result = await create_sandbox(image="openclaw/red:latest", label="recon-worker")
# result = {"sandbox_id": "...", "ip": "..."}
```

## Arguments

| Arg | Required | Description |
|-----|----------|-------------|
| `--image` | yes | Docker image to run (e.g. `openclaw/red:latest`, `openclaw/target:latest`) |
| `--label` | no | Human label attached for tracking and cleanup |
| `--env KEY=VAL` | no | Environment variable to inject (repeatable) |

## What it returns (stdout JSON)

```json
{
  "sandbox_id": "sb-abc123",
  "ip": "10.88.0.5",
  "status": "ready"
}
```

## Cleanup

Every sandbox ID is registered in the orchestrator's `_REGISTRY`. A SIGINT/SIGTERM
handler calls `daytona.remove(sandbox)` on all registered sandboxes automatically.
You do not need to manually destroy sandboxes unless you want to reclaim credits early.

## Credential flow

`DAYTONA_API_KEY` is read from the process environment. If you are using Jentic Mini,
register the key once via the Jentic UI and reference the toolkit key (`tk_xxx`) in your
`.env` — the key is injected at runtime and never appears in skill files or logs.
