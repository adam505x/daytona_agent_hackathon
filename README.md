# OpenClaw — Red/Blue Team Autonomous Security Pipeline

Autonomous security testing pipeline that **finds vulnerabilities** (red team) and
**opens patching PRs** (blue team) without human intervention.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         RED TEAM                                    │
│                                                                     │
│  red_team.py ──► spawn DVWA target sandbox                         │
│       │                                                             │
│       ├──► spawn recon sandbox ──► nmap + gobuster ──► findings    │
│       │                                                             │
│       └──► for each finding:                                        │
│              spawn exploit sandbox (parallel, asyncio)              │
│                └──► success? ──► spawn deeper sandboxes (fanout)   │
│                                                                     │
│                         ▼                                           │
│                  findings.json                                       │
└─────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        BLUE TEAM                                    │
│                                                                     │
│  blue_team.py ──► read findings.json                               │
│       │                                                             │
│       └──► for each successful finding:                             │
│              Claude agent (claude-sonnet-4-5-20251001)              │
│                ├── read_file(path) tool                             │
│                └── create_pr(branch, patches, desc) tool           │
│                      └──► GitHub PR opened                          │
└─────────────────────────────────────────────────────────────────────┘
```

## Repository layout

```
.
├── skills/
│   ├── daytona-spawn/SKILL.md   # Skill: provision a Daytona sandbox
│   ├── recon/SKILL.md           # Skill: nmap + gobuster recon
│   └── exploit/SKILL.md         # Skill: targeted exploitation
├── target/
│   ├── Dockerfile               # DVWA with verbose logging + auditd
│   ├── audit.rules              # auditd syscall rules
│   ├── process_watcher.sh       # Dumps procs every 5s to /var/log/procs.log
│   └── entrypoint.sh            # Starts all services
├── sandbox-images/
│   └── red.Dockerfile           # Attack tooling: nmap, gobuster, sqlmap, …
├── orchestrator/
│   ├── red_team.py              # Red team orchestrator (asyncio + Daytona SDK)
│   ├── blue_team.py             # Blue team orchestrator (Anthropic API + PyGithub)
│   └── requirements.txt
├── output/
│   └── findings.json            # Schema + populated by red_team.py
├── .env.example
└── README.md
```

## Quickstart

### 1. Prerequisites

- Python 3.11+
- Docker (to build images)
- A [Daytona](https://daytona.io) account and API key
- An [Anthropic](https://console.anthropic.com) API key
- A GitHub personal access token (`repo` scope)

### 2. One-command setup and run

```bash
git clone <this-repo> && cd daytona_agent_hackathon && \
cp .env.example .env && \
# ── fill in .env (DAYTONA_API_KEY, ANTHROPIC_API_KEY, GITHUB_TOKEN, GITHUB_REPO, TARGET_REPO_PATH) ── \
docker build -f sandbox-images/red.Dockerfile -t openclaw/red:latest . && \
docker build -f target/Dockerfile -t openclaw/dvwa-target:latest ./target && \
pip install -r orchestrator/requirements.txt && \
python orchestrator/red_team.py && \
python orchestrator/blue_team.py
```

### 3. Step-by-step

#### Build the images

```bash
# Red team attack image (used for all exploit sandboxes)
docker build -f sandbox-images/red.Dockerfile -t openclaw/red:latest .

# DVWA target with enhanced logging
docker build -f target/Dockerfile -t openclaw/dvwa-target:latest ./target
```

Then push both images to a registry accessible from your Daytona environment, or
set `TARGET_IMAGE` / `RED_IMAGE` in `.env` to point to existing public images.

#### Configure environment

```bash
cp .env.example .env
# Edit .env and fill in all required values
```

#### Run the red team

```bash
python orchestrator/red_team.py
```

This will:
1. Provision a DVWA sandbox via Daytona
2. Run recon (nmap + gobuster) from a separate sandbox
3. Fan out parallel exploit sandboxes for every finding
4. Recursively chase successful exploits (up to `MAX_DEPTH=3`)
5. Write all findings to `output/findings.json`

#### Run the blue team

```bash
python orchestrator/blue_team.py
# or point at a custom findings file:
python orchestrator/blue_team.py --findings /path/to/other_findings.json
```

This will:
1. Read `output/findings.json`
2. Spawn one Claude agent per unique finding
3. Each agent reads source files and crafts a minimal patch
4. Opens a GitHub PR for each finding
5. Writes PR URLs to `output/prs.json`

## Skills reference

| Skill | Description |
|---|---|
| [daytona-spawn](skills/daytona-spawn/SKILL.md) | Provision a Daytona sandbox, wait for readiness, return `{sandbox_id, ip}` |
| [recon](skills/recon/SKILL.md) | nmap full-port scan + gobuster path discovery → structured JSON |
| [exploit](skills/exploit/SKILL.md) | Targeted exploitation (sqlmap, hydra, curl, …) with recursive fan-out |

## `findings.json` schema

```jsonc
{
  "run_id":              "uuid",
  "timestamp":           "ISO-8601",
  "target_ip":           "string",
  "total_findings":      "int",
  "successful_exploits": "int",
  "findings": [
    {
      "id":           "uuid",
      "type":         "sqli | path_traversal | file_upload | brute_force | …",
      "severity":     "critical | high | medium | low",
      "target":       "ip:port/path",
      "success":      "bool",
      "evidence":     { ... },
      "raw_output":   "string (capped 5000 chars)",
      "sandbox_id":   "daytona-sandbox-uuid",
      "depth":        "int",
      "deeper_vectors": [ ... ],
      "error":        "string | null",
      "timestamp":    "ISO-8601"
    }
  ]
}
```

## Configuration reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `DAYTONA_API_KEY` | yes | — | Daytona API key |
| `DAYTONA_API_URL` | no | `https://app.daytona.io/api` | Daytona server URL |
| `TENSORIX_API_KEY` | yes | — | Tensorix API key (https://tensorix.ai) |
| `TENSORIX_API_URL` | no | `https://api.tensorix.ai` | Tensorix inference endpoint |
| `TENSORIX_MODEL` | no | `z-ai/glm-5` | Model for blue team agents (`z-ai/glm-5`, `kimi-k2.5`, `minimax-m2.5`, `deepseek-v3.1`) |
| `GITHUB_TOKEN` | yes | — | GitHub PAT with `repo` scope |
| `GITHUB_REPO` | yes | — | `owner/name` of the repo to open PRs against |
| `TARGET_REPO_PATH` | yes | `.` | Local path to the target repo (for blue team file reads) |
| `TARGET_IMAGE` | no | `vulnerables/web-dvwa:latest` | Docker image for DVWA target |
| `RED_IMAGE` | no | `openclaw/red:latest` | Docker image for attack sandboxes |
| `MAX_DEPTH` | no | `3` | Max exploit recursion depth |
| `MAX_PARALLEL` | no | `10` | Max concurrent exploit sandboxes |

## Security / ethics notice

This tooling is designed for **authorised security testing only**.
- Never target systems you do not own or have explicit written permission to test.
- The DVWA target is intentionally vulnerable and should only be run in isolated
  network environments.
- GitHub PRs will be opened against `GITHUB_REPO` — ensure this is a repo you control.
