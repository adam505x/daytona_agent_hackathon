import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from daytona import Daytona, DaytonaConfig, CodeRunParams
from dotenv import load_dotenv

load_dotenv()

DAYTONA_API_KEY = os.getenv("DAYTONA_API_KEY")
MAX_WORKERS = 5
PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# ── Step 1: Extract tasks from file using Claude ──────────────────────────────

def extract_tasks(file_path):
    with open(file_path) as f:
        content = f.read()

    prompt = """You are a task extraction agent. Read the document below and return a JSON array of tasks.

Each task must have:
- "id": integer starting at 1
- "topic": short label (< 10 words)
- "context": 1-2 sentences describing what the worker should do
- "priority": "high" | "medium" | "low"

Rules:
- high = security issues, critical bugs, blocking work
- medium = core features, main analysis
- low = docs, nice-to-haves, minor items

Return ONLY the JSON array, no explanation, no markdown fences.

Document:
""" + content[:8000]

    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)

    result = subprocess.run(
        ["claude", "-p", prompt],
        capture_output=True, text=True, timeout=60, env=env
    )

    raw = result.stdout.strip()
    if raw.startswith("```"):
        lines = raw.splitlines()
        raw = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

    return json.loads(raw)


# ── Step 2: Worker code that runs inside each VM ──────────────────────────────

WORKER_CODE = '''
import json, os, subprocess, re

task = json.loads(os.environ["TASK_JSON"])
print(f"Task {task['id']} [{task['priority']}]: {task['topic']}")

findings = []
context = task.get("context", "")

ip_match = re.search(r"(\\d{1,3}(?:\\.\\d{1,3}){3})(:\\d+)?(/\\S*)?", context)
if ip_match:
    target = ip_match.group(0)
    try:
        r = subprocess.run(["curl", "-sk", "--max-time", "10", f"http://{target}"],
                           capture_output=True, text=True)
        findings.append(f"HTTP probe {target}: {r.stdout[:500]}")
    except Exception as e:
        findings.append(f"Probe failed: {e}")
else:
    findings.append(context[:600])

print(json.dumps({
    "task_id": task["id"],
    "topic": task["topic"],
    "priority": task["priority"],
    "status": "ok",
    "findings": "\\n".join(findings),
}))
'''


# ── Step 3: Dispatch tasks to VMs ─────────────────────────────────────────────

def run_task(daytona, task):
    sandbox = None
    try:
        sandbox = daytona.create()
        print(f"  [+] VM {sandbox.id[:8]}  [{task['priority']}] {task['topic']}")

        result = sandbox.process.code_run(
            WORKER_CODE,
            params=CodeRunParams(env={"TASK_JSON": json.dumps(task)}),
        )

        if result.exit_code != 0:
            return {"task_id": task["id"], "topic": task["topic"],
                    "priority": task["priority"], "status": "error", "error": result.result}

        for line in reversed(result.result.strip().splitlines()):
            if line.strip().startswith("{"):
                return json.loads(line.strip())

        return {"task_id": task["id"], "topic": task["topic"],
                "priority": task["priority"], "status": "error", "error": "no JSON output"}

    except Exception as e:
        return {"task_id": task.get("id"), "topic": task.get("topic"),
                "priority": task.get("priority"), "status": "error", "error": str(e)}
    finally:
        if sandbox:
            try:
                daytona.delete(sandbox)
                print(f"  [-] VM {sandbox.id[:8]}  task {task['id']} done — slot free")
            except Exception:
                pass


def dispatch(tasks):
    daytona = Daytona(DaytonaConfig(api_key=DAYTONA_API_KEY))
    ordered = sorted(tasks, key=lambda t: PRIORITY_ORDER.get(t.get("priority", "medium"), 1))

    counts = {p: sum(1 for t in ordered if t.get("priority") == p) for p in PRIORITY_ORDER}
    print(f"\nQueue: {len(ordered)} tasks — high={counts['high']}  medium={counts['medium']}  low={counts['low']}")
    print(f"Concurrency: {MAX_WORKERS} VMs max\n")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(run_task, daytona, task): task for task in ordered}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.get("task_id") or 0)
    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def main(file_path):
    print(f"Step 1/3  Extracting tasks from: {file_path}")
    tasks = extract_tasks(file_path)
    print(f"          {len(tasks)} tasks extracted:")
    for t in tasks:
        print(f"          [{t['priority']:6}] {t['id']}. {t['topic']}")

    print(f"\nStep 2/3  Dispatching to Daytona VMs...")
    results = dispatch(tasks)

    print(f"\nStep 3/3  Saving findings...")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    os.makedirs("output", exist_ok=True)

    findings_path = "output/findings.json"
    try:
        with open(findings_path) as f:
            findings_log = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        findings_log = []

    for r in results:
        if r.get("status") == "ok":
            findings_log.append({
                "run_id": run_id,
                "source_file": file_path,
                "task_id": r["task_id"],
                "topic": r["topic"],
                "priority": r["priority"],
                "findings": r.get("findings", ""),
            })

    with open(findings_path, "w") as f:
        json.dump(findings_log, f, indent=2)

    ok = sum(1 for r in results if r.get("status") == "ok")
    print(f"\nDone: {ok}/{len(results)} succeeded  |  findings → {findings_path}")

    print("\n--- RESULTS SUMMARY ---")
    for r in results:
        status = "✓" if r.get("status") == "ok" else "✗"
        print(f"{status} [{r.get('priority','?'):6}] {r.get('topic','')}")
        if r.get("findings"):
            print(f"  {r['findings'][:200]}")
    print("--- END SUMMARY ---")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pipeline.py <file_path>")
        sys.exit(1)
    main(sys.argv[1])
