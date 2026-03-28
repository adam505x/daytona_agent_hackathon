"""
Sends uploaded file to Claude (via claude CLI) and returns a structured task list.
No separate API key needed — uses the active Claude Code session.
"""
import json
import os
import subprocess
import sys


PROMPT_TEMPLATE = """You are a task extraction agent. Read the document below and return a JSON array of tasks to be executed in parallel by worker agents.

Each task must have:
- "id": integer starting at 1
- "topic": short label (< 10 words)
- "context": 1-2 sentences describing exactly what the worker should do
- "priority": "high" | "medium" | "low"

Rules:
- High priority = security issues, blocking dependencies, critical bugs
- Medium priority = core features, main analysis tasks
- Low priority = nice-to-haves, documentation, minor items
- Return ONLY the JSON array, no explanation, no markdown fences

Document:
{content}"""


def extract_tasks(file_path: str) -> list[dict]:
    with open(file_path) as f:
        content = f.read()

    prompt = PROMPT_TEMPLATE.replace("{content}", content[:8000])

    print("Sending file to Claude for task extraction...")
    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)   # don't let a dummy key override Claude Code's auth

    result = subprocess.run(
        ["claude", "-p", prompt],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )

    if result.returncode != 0 or not result.stdout.strip():
        print(f"Claude CLI stdout: {repr(result.stdout[:300])}", file=sys.stderr)
        print(f"Claude CLI stderr: {repr(result.stderr[:300])}", file=sys.stderr)
        raise RuntimeError("Task extraction failed")

    raw = result.stdout.strip()

    # Strip markdown code fences if Claude wrapped the output
    if raw.startswith("```"):
        lines = raw.splitlines()
        raw = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

    tasks = json.loads(raw)
    return tasks
