"""
Runs INSIDE the Daytona VM.
Receives task via TASK_JSON env var.
Executes the task and prints a JSON result as the final line of stdout.
"""
import json
import os
import subprocess
import re

task = json.loads(os.environ["TASK_JSON"])
print(f"Task {task['id']} [{task['priority']}]: {task['topic']}")

findings = []
context = task.get("context", "")

# If context contains an IP target, probe it
ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?(/\S*)?", context)
if ip_match:
    target = ip_match.group(0)
    try:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", "10", f"http://{target}"],
            capture_output=True, text=True
        )
        findings.append(f"HTTP probe {target}: {r.stdout[:500]}")
    except Exception as e:
        findings.append(f"Probe failed: {e}")
else:
    # General task — record context for orchestrator to synthesise
    findings.append(context[:600])

result = {
    "task_id": task["id"],
    "topic": task["topic"],
    "priority": task["priority"],
    "status": "ok",
    "findings": "\n".join(findings),
}

print(json.dumps(result))
