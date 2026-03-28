# project-orc — Multi-Agent Orchestrator

Reads a file, uses Claude to extract topics/tasks, spawns parallel Daytona sandboxes
to research each one, then collects and saves all findings.

```
┌──────────────────────────────────────┐
│  main.py  (orchestrator)             │
│  1. extract_tasks(file) via Claude   │
│  2. dispatch(tasks) → sandboxes      │
│  3. collect results → output/        │
└──────────┬───────────────────────────┘
           │ up to MAX_WORKERS concurrent
     ┌─────┼─────┐
     ▼     ▼     ▼
  sandbox sandbox sandbox
  researcher.py (each has Claude access)
  → JSON result printed to stdout
  → sandbox removed immediately after
```

## Setup

```bash
git clone <repo> && cd project-orc
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in your keys
```

## Run

```bash
python orchestrator/main.py path/to/your/file.txt --type research
```

Options:
- `--type research` — extract and research topics (default)
- `--type code` — code-level analysis tasks
- `--type news` — fact-check claims in a news article
- `--output results.json` — custom output filename (saved in `output/`)

Results are written to `output/results_<timestamp>.json`.

## Test (no Daytona credits needed)

```bash
pytest tests/
```

## Disk limit

Daytona free tier = 30 GB. Each sandbox ≈ 1-2 GB.
`MAX_WORKERS=5` (default) means ≤ 5 sandboxes alive at once ≈ 5-10 GB peak.
Each sandbox is deleted immediately after its task completes.

## Project layout

```
project-orc/
├── orchestrator/
│   ├── main.py         # CLI entry point
│   ├── extractor.py    # Claude extracts tasks from input file
│   └── dispatcher.py   # Spawns sandboxes, collects results
├── workers/
│   ├── researcher.py   # Runs inside each sandbox
│   └── templates/
│       └── research_prompt.txt
├── shared/
│   ├── config.py       # Env vars
│   └── utils.py        # save_output, chunk_list, …
├── tests/
│   └── test_pipeline.py
├── output/             # Generated — gitignored
├── .env.example
├── requirements.txt
└── README.md
```
