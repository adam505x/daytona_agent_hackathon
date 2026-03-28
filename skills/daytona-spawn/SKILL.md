# Skill: daytona-spawn

## Purpose
Provision a Daytona sandbox via the Daytona MCP, wait until it is ready,
and return its sandbox ID and reachable IP address. Used by all OpenClaw
orchestrators to create ephemeral, isolated execution environments.

## Trigger phrase
`spawn sandbox [image] [commands...]`
or when an orchestrator step requires `$DAYTONA_SANDBOX`.

## Inputs

| Field | Type | Required | Description |
|---|---|---|---|
| `image` | string | yes | Docker image name to use (e.g. `openclaw/red:latest`) |
| `startup_commands` | string[] | no | Shell commands to run after the sandbox starts |
| `env` | object | no | Environment variables to inject into the sandbox |
| `resources` | object | no | Optional CPU/memory overrides `{cpu: int, memory: int}` |
| `label` | string | no | Human-readable label attached to the sandbox for tracking |

## Outputs

| Field | Type | Description |
|---|---|---|
| `sandbox_id` | string | Daytona sandbox UUID, used for all subsequent MCP calls |
| `ip` | string | Internal IP address of the running sandbox |
| `status` | `"ready" \| "error"` | Whether the sandbox came up cleanly |
| `error` | string | Present only when `status == "error"` |

## Algorithm

```
1. Call mcp__daytona-mcp__create_sandbox with:
     image  = inputs.image
     env    = inputs.env  (if provided)
     labels = { "openclaw.label": inputs.label }

2. Poll mcp__daytona-mcp__execute_command("echo ready") until it returns
   exit_code=0  OR  30-second timeout.

3. If startup_commands provided, run each via mcp__daytona-mcp__execute_command
   in sequence; abort on non-zero exit and surface the error.

4. Resolve the sandbox IP:
     result = mcp__daytona-mcp__execute_command("hostname -I | awk '{print $1}'")
     ip = result.output.strip()

5. Return { sandbox_id, ip, status: "ready" }
```

## Error handling
- If `create_sandbox` fails: return `{ status: "error", error: <message> }`.
- If readiness poll times out: call `mcp__daytona-mcp__destroy_sandbox(sandbox_id)`
  then return `{ status: "error", error: "timeout waiting for sandbox" }`.
- If a startup command fails: destroy the sandbox and surface the failed command
  and its stderr in the error field.

## Example invocation (OpenClaw YAML)

```yaml
- skill: daytona-spawn
  inputs:
    image: "openclaw/red:latest"
    label: "recon-worker-1"
    env:
      TARGET_IP: "{{ target.ip }}"
    startup_commands:
      - "nmap --version"
      - "gobuster version"
  outputs:
    - sandbox_id -> recon_sandbox_id
    - ip         -> recon_sandbox_ip
```

## Example invocation (Python)

```python
from skills.daytona_spawn import spawn_sandbox

result = await spawn_sandbox(
    image="openclaw/red:latest",
    startup_commands=["nmap --version"],
    env={"TARGET_IP": target_ip},
    label="recon-worker",
)
assert result["status"] == "ready"
sandbox_id = result["sandbox_id"]
ip = result["ip"]
```

## Notes
- Sandboxes are **not** automatically destroyed by this skill; the calling
  orchestrator is responsible for cleanup via `mcp__daytona-mcp__destroy_sandbox`.
- All sandbox IDs are registered in the orchestrator's `SandboxRegistry` so
  a SIGINT/crash handler can clean up orphaned sandboxes.
- The `label` field is propagated to findings so analysts can trace which
  sandbox produced which evidence.
