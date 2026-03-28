# Skill: recon

## Purpose
Run a full reconnaissance sweep against a target IP using **nmap** and
**gobuster** inside an existing Daytona sandbox. Returns structured JSON
describing open ports, running services, and discovered HTTP paths. This
output feeds directly into the `exploit` skill.

## Trigger phrase
`recon [target_ip] in sandbox [sandbox_id]`
or when an orchestrator step produces `$RECON_FINDINGS`.

## Inputs

| Field | Type | Required | Description |
|---|---|---|---|
| `sandbox_id` | string | yes | Daytona sandbox to run tools inside |
| `target_ip` | string | yes | IP (or hostname) of the system to probe |
| `ports` | string | no | nmap port range, default `"1-65535"` |
| `wordlist` | string | no | gobuster wordlist path inside the sandbox image, default `/usr/share/wordlists/dirb/common.txt` |
| `http_ports` | int[] | no | Ports to run gobuster against, default `[80, 8080, 443, 8443]` |
| `timeout_seconds` | int | no | Max wall-clock time per tool, default `120` |

## Outputs

```jsonc
{
  "target": "192.168.1.100",
  "sandbox_id": "abc123",
  "ports": [
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "version": "Apache httpd 2.4.54"
    }
  ],
  "paths": [
    {
      "path": "/login.php",
      "status": 200,
      "size": 4321,
      "port": 80
    },
    {
      "path": "/setup.php",
      "status": 200,
      "size": 1980,
      "port": 80
    }
  ],
  "raw_nmap": "<full nmap XML output>",
  "raw_gobuster": "<full gobuster output per port>",
  "error": null
}
```

## Algorithm

```
1. nmap sweep
   cmd = f"nmap -sV -sC -T4 -p {ports} --open -oX /tmp/nmap_out.xml {target_ip}"
   run via mcp__daytona-mcp__execute_command(sandbox_id, cmd, timeout=timeout_seconds)

   Parse /tmp/nmap_out.xml:
     - extract each <port> where state[@state="open"]
     - extract service name + version string

2. HTTP path discovery (parallel per http_port)
   For each port in http_ports that appears in nmap results as "open":
     cmd = f"gobuster dir -u http://{target_ip}:{port} -w {wordlist} -o /tmp/gobuster_{port}.txt -q --no-error"
     run via mcp__daytona-mcp__execute_command(sandbox_id, cmd, timeout=timeout_seconds)
     Parse /tmp/gobuster_{port}.txt for lines matching:
       "/{path} (Status: {code}) [Size: {bytes}]"

3. Assemble output JSON and return.
```

## Error handling
- If nmap exits non-zero: set `error` field, return partial results (empty `ports`).
- If gobuster exits non-zero for a specific port: record `{ path: null, status: null, error: "gobuster failed on port X" }` and continue other ports.
- Individual tool errors never abort the entire recon; findings are always returned even if partial.

## Severity heuristics (attached to each finding for exploit triage)

| Condition | Severity |
|---|---|
| Port 22 open + version fingerprint | medium |
| Port 80/443 + PHP paths ending in `.php` | high |
| `/admin`, `/setup`, `/config`, `/phpmyadmin` found | critical |
| MySQL (3306) or PostgreSQL (5432) exposed | critical |
| Any path returning 200 with "login" in name | high |

## Example invocation (Python)

```python
from skills.recon import run_recon

findings = await run_recon(
    sandbox_id=recon_sandbox_id,
    target_ip="10.0.0.5",
    http_ports=[80],
    timeout_seconds=180,
)
# findings["ports"]  -> list of port dicts
# findings["paths"]  -> list of path dicts
```

## Notes
- This skill is **read-only and non-destructive**; it sends no exploit payloads.
- nmap's `-sC` flag runs default NSE scripts which may trigger IDS alerts on
  hardened targets; disable with `nmap_scripts=False` if stealth is required.
- gobuster wordlists are baked into `openclaw/red:latest`; custom wordlists
  can be uploaded via `mcp__daytona-mcp__file_upload` before invoking this skill.
