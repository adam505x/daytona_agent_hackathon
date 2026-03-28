#!/usr/bin/env python3
"""
Entry point for the AI Task Orchestrator.

Usage:
  python orchestrator/main.py <file_path>

OpenClaw calls this when a file is uploaded.
Results are written to output/results.json and printed to stdout.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from orchestrator.extractor import extract_tasks
from orchestrator.dispatcher import dispatch
from shared.utils import save_output



def main():
    parser = argparse.ArgumentParser(description="AI Task Orchestrator — Daytona VM pipeline")
    parser.add_argument("file", help="Path to the file to process")
    parser.add_argument("--output", default="results.json", help="Output filename in output/")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Step 1: Extract tasks from file using Claude
    print(f"Step 1/3  Extracting tasks from: {args.file}")
    tasks = extract_tasks(args.file)
    print(f"          {len(tasks)} tasks extracted:")
    for t in tasks:
        print(f"          [{t['priority']:6}] {t['id']}. {t['topic']}")

    # Step 2: Dispatch to Daytona VMs
    print(f"\nStep 2/3  Dispatching to Daytona VMs...")
    results = dispatch(tasks)

    # Step 3: Save results and findings
    print(f"\nStep 3/3  Saving results...")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


    output = {
        "run_id": run_id,
        "source_file": args.file,
        "total_tasks": len(tasks),
        "completed": sum(1 for r in results if r.get("status") != "error"),
        "failed": sum(1 for r in results if r.get("status") == "error"),
        "tasks": tasks,
        "results": results,
    }
    path = save_output(output, args.output)

    # Write findings.json — successful results only, appending to existing runs
    findings_path = os.path.join("output", "findings.json")
    try:
        with open(findings_path) as f:
            findings_log = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        findings_log = []

    for r in results:
        if r.get("status") == "ok" and r.get("findings"):
            findings_log.append({
                "run_id": run_id,
                "source_file": args.file,
                "task_id": r["task_id"],
                "topic": r["topic"],
                "priority": r["priority"],
                "findings": r["findings"],
            })

    with open(findings_path, "w") as f:
        json.dump(findings_log, f, indent=2)

    ok = output["completed"]
    fail = output["failed"]
    print(f"\nDone: {ok}/{len(results)} succeeded  |  results → {path}  |  findings → {findings_path}")

    # Print summary for OpenClaw to pick up
    print("\n--- RESULTS SUMMARY ---")
    for r in results:
        status = "✓" if r.get("status") != "error" else "✗"
        print(f"{status} [{r.get('priority','?'):6}] {r.get('topic','')}")
        if r.get("findings"):
            print(f"  {r['findings'][:200]}")
    print("--- END SUMMARY ---")


if __name__ == "__main__":
    main()
