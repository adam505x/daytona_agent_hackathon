"""
Priority-sorts tasks (high → medium → low), manages a 5-slot concurrency queue.
Each task gets its own ephemeral Daytona VM — created, used, destroyed.
When a VM finishes, the next task in the queue claims the slot.
"""
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from daytona import Daytona, DaytonaConfig, CodeRunParams

from shared.config import DAYTONA_API_KEY, MAX_WORKERS

WORKER_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "workers", "researcher.py")

PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _run_task(daytona: Daytona, task: dict) -> dict:
    """Spin up a VM, run the task, destroy the VM, return result."""
    sandbox = None
    try:
        sandbox = daytona.create()
        print(f"  [+] VM {sandbox.id[:8]}  task {task['id']} [{task['priority']}] {task['topic']}")

        with open(WORKER_SCRIPT) as f:
            worker_code = f.read()

        result = sandbox.process.code_run(
            worker_code,
            params=CodeRunParams(env={"TASK_JSON": json.dumps(task)}),
        )

        if result.exit_code != 0:
            return {
                "task_id": task["id"],
                "topic": task["topic"],
                "priority": task["priority"],
                "status": "error",
                "error": result.result,
            }

        # Worker prints JSON as its last line
        for line in reversed(result.result.strip().splitlines()):
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)

        return {
            "task_id": task["id"],
            "topic": task["topic"],
            "priority": task["priority"],
            "status": "error",
            "error": "no JSON result from worker",
            "raw": result.result,
        }

    except Exception as e:
        return {
            "task_id": task.get("id"),
            "topic": task.get("topic"),
            "priority": task.get("priority"),
            "status": "error",
            "error": str(e),
        }
    finally:
        if sandbox:
            try:
                daytona.delete(sandbox)
                print(f"  [-] VM {sandbox.id[:8]}  task {task['id']} done — slot free")
            except Exception:
                pass


def dispatch(tasks: list[dict]) -> list[dict]:
    """
    Run all tasks across max MAX_WORKERS (5) concurrent VMs.
    Tasks are submitted in priority order so the thread pool picks
    up high-priority work first as slots become available.
    """
    daytona = Daytona(DaytonaConfig(api_key=DAYTONA_API_KEY))

    ordered = sorted(tasks, key=lambda t: PRIORITY_ORDER.get(t.get("priority", "medium"), 1))

    counts = {p: sum(1 for t in ordered if t.get("priority") == p) for p in PRIORITY_ORDER}
    print(f"\nQueue: {len(ordered)} tasks — "
          f"high={counts['high']}  medium={counts['medium']}  low={counts['low']}")
    print(f"Concurrency: {MAX_WORKERS} VMs max\n")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_run_task, daytona, task): task for task in ordered}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.get("task_id") or 0)
    return results
