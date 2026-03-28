# OpenClaw Red/Blue Team Security Pipeline

Autonomous security pipeline: a red team agent finds vulnerabilities, a blue team
agent patches them and opens GitHub PRs — no human in the loop.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  HOST MACHINE                                                               │
│                                                                             │
│  OpenClaw (Node.js gateway)                                                 │
│    reads skills/ → embeds into agent system prompt                         │
│    agent calls exec("python3 orchestrator/red_team.py")                    │
│         │                                                                   │
│         ▼                                                                   │
│  Jentic Mini (Docker, port 8900)                                            │
│    credential vault — injects DAYTONA_API_KEY, ANTHROPIC_API_KEY,          │
│    GITHUB_TOKEN at runtime so keys are never in skill files or code         │
│         │                                                                   │
│         ▼                                                                   │
│  red_team.py (Python + Daytona SDK + asyncio)                               │
│    │                                                                        │
│    ├── Daytona API → target sandbox (Harbinger Flask app)                  │
│    │     └── snapshot immediately → --reset restores this for demo replay  │
│    │                                                                        │
│    ├── Daytona API → recon sandbox                                          │
│    │     └── nmap + gobuster → structured findings JSON                    │
│    │                                                                        │
│    └── Daytona API → exploit sandboxes (parallel, asyncio.gather)          │
│          └── success? → fan out deeper sandboxes (capped at MAX_DEPTH=3)   │
│                                                                             │
│                      ▼                                                      │
│               output/findings.json                                          │
│                      │                                                      │
│  blue_team.py (Python + Anthropic API raw tool_use + PyGithub)              │
│    └── one Claude agent per finding                                         │
│          ├── read_file tool → reads target/app.py                          │
│          └── create_pr tool → GitHub PR with patch                         │
│                      ▼                                                      │
│               output/prs.json + GitHub PRs                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Target: Harbinger Inventory API

A custom vulnerable Flask app (`target/app.py`) — NOT DVWA. Three subtle
vulnerabilities that are not publicly documented, so the agent must actually
probe to find them:

| # | Endpoint | Technique | Subtlety |
|---|----------|-----------|----------|
| 1 | `GET /api/inventory?sort=` | SQL injection (ORDER BY clause) | The `query` param is safe (red herring); the `sort` param is injectable but starts with a valid column name |
| 2 | `GET /api/report?name=` | Path traversal (os.path.join absolute-path bypass) | `..` is blocked but `/etc/passwd` as an absolute path silently discards the base dir |
| 3 | `POST /api/diagnostics` | Command injection (incomplete blacklist) | Filter blocks `;`, `\|`, single `&`, `` ` ``, `$` but `&&` (as unicode escape `\u0026\u0026`) bypasses |

## Repository layout

```
.
├── skills/
│   ├── daytona-spawn/SKILL.md   ← OpenClaw skill: provision a Daytona sandbox
│   ├── recon/SKILL.md           ← OpenClaw skill: nmap + gobuster
│   └── exploit/SKILL.md         ← OpenClaw skill: targeted exploitation + fan-out
├── target/
│   ├── app.py                   ← Harbinger vulnerable Flask app
│   ├── Dockerfile               ← Flask + auditd + process watcher
│   ├── requirements.txt
│   ├── audit.rules              ← auditd syscall rules
│   ├── process_watcher.sh       ← dumps ps/ss/lsof every 5s → /var/log/procs.log
│   └── entrypoint.sh
├── sandbox-images/
│   ├── red.Dockerfile           ← nmap, gobuster, sqlmap, pwntools, curl
│   └── openclaw-api-wordlist.txt
├── orchestrator/
│   ├── red_team.py              ← full pipeline + snapshot/restore + --reset flag
│   ├── blue_team.py             ← Anthropic tool_use agents + PyGithub PRs
│   └── requirements.txt
├── dvwa/                        ← git submodule (adam505x/DVWA_Daytona_Hackathon)
├── output/
│   └── findings.json            ← schema + populated at runtime by red_team.py
├── docker-compose.yml           ← Jentic Mini + target + red toolbox (local dev)
├── Makefile
├── .env.example
└── README.md
```

## Quickstart

### 1. Prerequisites

- [OpenClaw](https://github.com/openclaw/openclaw): `npm install -g openclaw@latest && openclaw onboard --install-daemon`
- [Docker](https://docs.docker.com/get-docker/) (for images and Jentic Mini)
- Python 3.11+
- A [Daytona](https://daytona.io) account and API key
- An [Anthropic](https://console.anthropic.com) API key
- A GitHub PAT with `repo` scope

### 2. One-command local smoke test

```bash
git clone --recurse-submodules <this-repo> && cd daytona_agent_hackathon
cp .env.example .env              # fill in API keys
make up                           # builds images, starts Jentic Mini + target + red toolbox
```

Harbinger API: http://localhost:5000
Jentic Mini UI: http://localhost:8900

### 3. Set up Jentic Mini

```bash
# Open http://localhost:8900 in your browser
# Add credentials:
#   POST /credentials  { "api_id": "daytona", "values": { "api_key": "..." } }
#   POST /credentials  { "api_id": "anthropic", "values": { "api_key": "..." } }
#   POST /credentials  { "api_id": "github", "values": { "token": "..." } }
# Generate a toolkit key → copy the tk_xxx value into .env as JENTIC_TOOLKIT_KEY
```

### 4. Install and configure OpenClaw

```bash
openclaw onboard --install-daemon   # first time only
# OpenClaw auto-discovers skills in ./skills/ when launched from this directory
openclaw gateway --port 18789 --verbose
```

OpenClaw will find `skills/daytona-spawn/`, `skills/recon/`, and `skills/exploit/`
and embed them into the agent's system prompt. Tell the agent:

```
"Run the red team pipeline against the Harbinger target"
```

OpenClaw will invoke the skills, calling `python3 orchestrator/red_team.py` via exec.

### 5. Run standalone (without OpenClaw)

```bash
pip install -r orchestrator/requirements.txt

# Full red team pipeline
python3 orchestrator/red_team.py

# Reset target to clean snapshot (for demo replay)
python3 orchestrator/red_team.py --reset

# Blue team (reads findings.json, opens GitHub PRs)
python3 orchestrator/blue_team.py
```

### 6. Push images to a registry (required for Daytona)

```bash
make push REGISTRY=docker.io/yourusername
# Then set TARGET_IMAGE and RED_IMAGE in .env to point to your registry
```

## Demo replay

After the first run, the target is snapshotted automatically.
To replay the demo from a clean state:

```bash
python3 orchestrator/red_team.py --reset   # restores target from snapshot
python3 orchestrator/red_team.py           # runs the pipeline again
python3 orchestrator/blue_team.py          # opens PRs for new findings
```

## Makefile commands

```
make up          build all images + start local stack
make down        stop and remove containers
make shell-red   open a bash shell in the red toolbox
make shell-target open a bash shell in the Harbinger target
make logs        tail target access + process logs
make install     pip install -r orchestrator/requirements.txt
make red         run red_team.py
make blue        run blue_team.py
make push        push images to REGISTRY
```

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `DAYTONA_API_KEY` | yes | — | Daytona API key |
| `DAYTONA_API_URL` | no | `https://app.daytona.io/api` | Daytona server |
| `ANTHROPIC_API_KEY` | yes | — | Anthropic API key |
| `BLUE_TEAM_MODEL` | no | `claude-sonnet-4-6` | Model for blue team agents |
| `GITHUB_TOKEN` | yes | — | GitHub PAT (repo scope) |
| `GITHUB_REPO` | yes | — | `owner/name` to open PRs against |
| `TARGET_REPO_PATH` | no | `.` | Local repo path for blue team file reads |
| `JENTIC_VAULT_KEY` | no | auto | Jentic Mini vault encryption key |
| `JENTIC_TOOLKIT_KEY` | no | — | Jentic Mini agent toolkit key (`tk_xxx`) |
| `TARGET_IMAGE` | no | `openclaw/target:latest` | Daytona target image |
| `RED_IMAGE` | no | `openclaw/red:latest` | Daytona attack image |
| `MAX_DEPTH` | no | `3` | Exploit fan-out recursion cap |
| `MAX_PARALLEL` | no | `8` | Max concurrent exploit sandboxes |
| `SNAPSHOT_NAME` | no | `openclaw-target-clean` | Name for --reset snapshot |

## Security notice

This pipeline is for **authorised security testing only**. The Harbinger target
contains intentional vulnerabilities. Never deploy it on a public network.
