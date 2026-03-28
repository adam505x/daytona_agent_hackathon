---
name: orchestrate
description: Take a file uploaded by the user, extract tasks using Claude, execute them in parallel across ephemeral Daytona VMs (max 5 concurrent, priority-ordered), log all findings to output/findings.json, and return a structured summary.
version: 1.0.0
metadata:
  openclaw:
    requires:
      env:
        - DAYTONA_API_KEY
      bins:
        - python3
        - claude
    primaryEnv: DAYTONA_API_KEY
    emoji: "⚡"
---

# Skill: orchestrate

Use this skill when a user uploads a file and wants it analysed, processed, or investigated by parallel agents.

## When to invoke

- User uploads or provides a file and says "analyse this", "run the pipeline", "process this", "investigate this"
- Any file type: `.txt`, `.json`, `.md`, `.py`, `.csv`
- User asks for a report or findings on a document

## How to invoke

```bash
cd /home/david/Documents/Daytona/daytona_agent_hackathon/project-orc && \
/home/david/venv/bin/python orchestrator/main.py <file_path>
```

Read the full stdout. Present the block between `--- RESULTS SUMMARY ---` and `--- END SUMMARY ---` to the user.

## What happens step by step

### Step 1 — Task extraction
`extractor.py` reads the file and calls `claude -p` to extract a prioritised task list:
```json
[
  { "id": 1, "topic": "Fix SQL injection", "context": "...", "priority": "high" },
  { "id": 2, "topic": "Improve search performance", "context": "...", "priority": "medium" }
]
```
Priority rules Claude follows:
- `high` — security issues, critical bugs, blocking dependencies
- `medium` — core features, main analysis tasks
- `low` — documentation, nice-to-haves, minor items

### Step 2 — Parallel VM dispatch
`dispatcher.py` sorts tasks `high → medium → low` and fills a 5-slot concurrency queue:
- Each task gets its own ephemeral Daytona VM
- Max 5 VMs alive at any time — as one finishes and is deleted, the next task claims the slot
- Each VM runs `workers/researcher.py` with the task injected via `TASK_JSON` env var
- VM is destroyed immediately after its task completes

### Step 3 — Results and findings logging
Two files are written to `output/`:

**`output/results.json`** — full run data (overwritten each run):
```json
{
  "run_id": "20240328T143000Z",
  "source_file": "path/to/file.txt",
  "total_tasks": 5,
  "completed": 5,
  "failed": 0,
  "tasks": [...],
  "results": [...]
}
```

**`output/findings.json`** — persistent log, appended across runs:
```json
[
  {
    "run_id": "20240328T143000Z",
    "source_file": "path/to/file.txt",
    "task_id": 1,
    "topic": "Fix SQL injection in authentication system",
    "priority": "high",
    "findings": "..."
  }
]
```
Only successful tasks are logged to `findings.json`. Failed tasks appear in `results.json` only.

## stdout format

```
Step 1/3  Extracting tasks from: <file>
          N tasks extracted:
          [high  ] 1. <topic>
          [medium] 2. <topic>
          [low   ] 3. <topic>

Step 2/3  Dispatching to Daytona VMs...

Queue: N tasks — high=X  medium=Y  low=Z
Concurrency: 5 VMs max

  [+] VM <id>  task <n> [<priority>] <topic>    ← VM created
  [-] VM <id>  task <n> done — slot free         ← VM destroyed

Step 3/3  Saving results...

Done: N/N succeeded  |  results → output/results.json  |  findings → output/findings.json

--- RESULTS SUMMARY ---
✓ [high  ] <topic>
  <findings preview>
✗ [low   ] <topic>     ← failed tasks show ✗
--- END SUMMARY ---
```

## Arguments

| Arg | Required | Default | Description |
|-----|----------|---------|-------------|
| `file_path` | yes | — | Path to the uploaded file |
| `--output` | no | `results.json` | Filename for results inside `output/` |

## Disk and concurrency limits

| Metric | Value |
|--------|-------|
| Max concurrent VMs | 5 |
| Disk per VM | ~1-2 GB |
| Peak disk usage | ~5-10 GB |
| Daytona free tier limit | 30 GB |
| VMs destroyed after task | ✓ always |

## Error handling

- If a VM fails to create (e.g. disk quota exceeded), the task is marked `error` in results but the pipeline continues
- If the worker script crashes, `exit_code != 0` is caught and logged
- `findings.json` only contains successful results — errors never pollute the findings log

## Credential flow

`DAYTONA_API_KEY` is read from `project-orc/.env` at startup via `python-dotenv`.
Never hardcode keys in skill files or source code.
The `claude` CLI uses its own session auth — no `ANTHROPIC_API_KEY` needed.
