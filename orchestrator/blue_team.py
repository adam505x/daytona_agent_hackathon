"""
blue_team.py — OpenClaw Blue Team Orchestrator

Architecture:
  1. Reads /output/findings.json produced by red_team.py
  2. For each successful finding, spawns an independent Tensorix agent via the
     Anthropic SDK (custom base_url) with tool_use
  3. Each agent has two tools:
       - read_file(path)  — reads source files from the target repo
       - create_pr(branch, files_changed, description) — opens a GitHub PR
  4. The agent reasons about the vulnerability and calls create_pr with a concrete patch
  5. All PR URLs are logged to /output/prs.json

Usage:
    python orchestrator/blue_team.py [--findings /output/findings.json]

Environment variables (see .env.example):
    TENSORIX_API_KEY   — Tensorix API key
    TENSORIX_API_URL   — Tensorix base URL (default: https://api.tensorix.ai)
    TENSORIX_MODEL     — Model to use (default: z-ai/glm-5)
    GITHUB_TOKEN       — Personal access token with repo scope
    GITHUB_REPO        — Target repo in owner/name format (e.g. "acme/dvwa-patched")
    TARGET_REPO_PATH   — Local filesystem path to the target repo (for read_file)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic
from dotenv import load_dotenv
from github import Github, GithubException

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────────────
TENSORIX_API_KEY   = os.environ["TENSORIX_API_KEY"]
TENSORIX_API_URL   = os.getenv("TENSORIX_API_URL", "https://api.tensorix.ai")
MODEL              = os.getenv("TENSORIX_MODEL", "z-ai/glm-5")
GITHUB_TOKEN       = os.environ["GITHUB_TOKEN"]
GITHUB_REPO        = os.environ["GITHUB_REPO"]
TARGET_REPO_PATH   = Path(os.getenv("TARGET_REPO_PATH", "."))
MAX_AGENT_TURNS    = 12
FINDINGS_PATH      = Path(__file__).parent.parent / "output" / "findings.json"
PRS_OUTPUT_PATH    = Path(__file__).parent.parent / "output" / "prs.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("blue_team")

# ── Tool definitions (Anthropic tool_use schema) ───────────────────────────────

TOOLS = [
    {
        "name": "read_file",
        "description": (
            "Read a file from the target repository. Use this to understand the "
            "vulnerable code before proposing a patch. Path must be relative to "
            "the repository root (e.g. 'src/login.php')."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path within the repository (e.g. 'src/login.php')",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "create_pr",
        "description": (
            "Create a GitHub Pull Request with one or more file patches that fix "
            "the identified vulnerability. Call this exactly once when you are "
            "confident you have a complete, tested patch."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "branch": {
                    "type": "string",
                    "description": "New branch name for the fix (e.g. 'fix/sqli-login-2024-01')",
                },
                "files_changed": {
                    "type": "array",
                    "description": "List of file patches to apply",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Relative file path in the repo",
                            },
                            "content": {
                                "type": "string",
                                "description": "Full new content of the file after patching",
                            },
                        },
                        "required": ["path", "content"],
                    },
                },
                "description": {
                    "type": "string",
                    "description": "PR description explaining the vulnerability and the fix",
                },
            },
            "required": ["branch", "files_changed", "description"],
        },
    },
]


# ── Tool implementations ───────────────────────────────────────────────────────

def _tool_read_file(path: str) -> str:
    """Read a file from the target repo. Sandboxes path to TARGET_REPO_PATH."""
    # Prevent directory traversal
    safe_path = Path(path).resolve()
    repo_root = TARGET_REPO_PATH.resolve()
    try:
        target = (repo_root / path).resolve()
        if not str(target).startswith(str(repo_root)):
            return "ERROR: Path traversal attempt blocked."
        if not target.exists():
            return f"ERROR: File not found: {path}"
        content = target.read_text(encoding="utf-8", errors="replace")
        if len(content) > 20_000:
            content = content[:20_000] + "\n... [truncated at 20000 chars]"
        return content
    except Exception as exc:
        return f"ERROR: {exc}"


def _tool_create_pr(
    branch: str,
    files_changed: list[dict],
    description: str,
    finding_id: str,
    gh_repo: Any,
) -> dict:
    """Create a GitHub PR with the patched files."""
    # Sanitise branch name
    safe_branch = re.sub(r"[^a-zA-Z0-9._/-]", "-", branch)[:80]
    if not safe_branch.startswith(("fix/", "patch/", "security/")):
        safe_branch = f"fix/{safe_branch}"

    log.info("Creating PR on branch %s with %d file(s)", safe_branch, len(files_changed))

    try:
        default_branch = gh_repo.default_branch
        base_sha = gh_repo.get_branch(default_branch).commit.sha

        # Create branch
        try:
            gh_repo.create_git_ref(ref=f"refs/heads/{safe_branch}", sha=base_sha)
        except GithubException as e:
            if e.status == 422:
                # Branch already exists — append suffix
                safe_branch = f"{safe_branch}-{uuid.uuid4().hex[:6]}"
                gh_repo.create_git_ref(ref=f"refs/heads/{safe_branch}", sha=base_sha)
            else:
                raise

        # Commit each file
        for file_patch in files_changed:
            file_path = file_patch["path"]
            new_content = file_patch["content"]
            commit_msg = f"security: patch {file_path} — finding {finding_id}"

            try:
                existing = gh_repo.get_contents(file_path, ref=safe_branch)
                gh_repo.update_file(
                    path=file_path,
                    message=commit_msg,
                    content=new_content,
                    sha=existing.sha,
                    branch=safe_branch,
                )
            except GithubException:
                # File doesn't exist yet — create it
                gh_repo.create_file(
                    path=file_path,
                    message=commit_msg,
                    content=new_content,
                    branch=safe_branch,
                )

        # Open PR
        pr_title = f"[Security] Automated patch for finding {finding_id}"
        pr_body = (
            f"## Automated Security Fix\n\n"
            f"**Finding ID:** `{finding_id}`\n\n"
            f"{description}\n\n"
            f"---\n"
            f"*Generated by OpenClaw Blue Team Orchestrator*"
        )
        pr = gh_repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=safe_branch,
            base=default_branch,
        )
        log.info("PR created: %s", pr.html_url)
        return {"success": True, "pr_url": pr.html_url, "pr_number": pr.number}

    except Exception as exc:
        log.error("PR creation failed: %s", exc)
        return {"success": False, "error": str(exc)}


# ── Agent ──────────────────────────────────────────────────────────────────────

def _system_prompt(finding: dict) -> str:
    return f"""You are a senior application-security engineer on the blue team.
You have been given a confirmed vulnerability finding from an automated red team scan.

Your job:
1. Read the relevant source files from the target repository using the read_file tool.
2. Understand exactly what code is vulnerable and why.
3. Write a minimal, correct patch that fixes the vulnerability without breaking functionality.
4. Call create_pr exactly once with:
   - A concise branch name (e.g. fix/sqli-login-php)
   - The complete patched file contents (not a diff — the full new file)
   - A clear PR description explaining the vulnerability class, root cause, and fix

Vulnerability finding details:
{json.dumps(finding, indent=2)}

Common fix patterns:
- SQL injection: use prepared statements / parameterised queries
- Path traversal: use realpath() + validate prefix; use basename() for filenames
- File upload: validate MIME type server-side; randomise filename; store outside webroot
- Brute force / auth bypass: add rate limiting, account lockout, CSRF tokens
- Command injection: use escapeshellarg(); prefer library APIs over shell commands

Be surgical. Only modify the lines that are vulnerable. Preserve all existing logic.
Do NOT add unnecessary dependencies or refactor unrelated code.
"""


async def _run_agent(finding: dict, gh_repo: Any) -> dict:
    """Run a single blue-team agent for one finding. Returns PR result dict."""
    finding_id = finding.get("id", str(uuid.uuid4())[:8])
    log.info("Agent starting for finding %s (%s)", finding_id, finding.get("type", "?"))

    client = anthropic.Anthropic(api_key=TENSORIX_API_KEY, base_url=TENSORIX_API_URL)
    messages: list[dict] = []
    pr_result: dict = {"success": False, "error": "agent did not call create_pr"}

    # Seed with initial user message
    messages.append({
        "role": "user",
        "content": (
            f"Please analyse finding {finding_id} and create a PR with a patch. "
            f"Start by reading the relevant source files."
        ),
    })

    for turn in range(MAX_AGENT_TURNS):
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=_system_prompt(finding),
            tools=TOOLS,
            messages=messages,
        )

        # Append assistant turn
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            log.info("Agent for %s finished (end_turn) after %d turns", finding_id, turn + 1)
            break

        if response.stop_reason != "tool_use":
            log.warning("Unexpected stop_reason: %s", response.stop_reason)
            break

        # Process tool calls
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue

            tool_name = block.name
            tool_input = block.input
            tool_use_id = block.id

            if tool_name == "read_file":
                result_text = _tool_read_file(tool_input["path"])
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": result_text,
                })

            elif tool_name == "create_pr":
                pr_result = _tool_create_pr(
                    branch=tool_input["branch"],
                    files_changed=tool_input["files_changed"],
                    description=tool_input["description"],
                    finding_id=finding_id,
                    gh_repo=gh_repo,
                )
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": json.dumps(pr_result),
                })
                # Once PR is created, we can stop
                if pr_result.get("success"):
                    messages.append({"role": "user", "content": tool_results})
                    log.info(
                        "PR created for finding %s: %s",
                        finding_id,
                        pr_result.get("pr_url"),
                    )
                    return {
                        "finding_id": finding_id,
                        "finding_type": finding.get("type"),
                        "severity": finding.get("severity"),
                        **pr_result,
                    }
            else:
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": f"ERROR: Unknown tool '{tool_name}'",
                    "is_error": True,
                })

        if tool_results:
            messages.append({"role": "user", "content": tool_results})

    return {
        "finding_id": finding_id,
        "finding_type": finding.get("type"),
        "severity": finding.get("severity"),
        **pr_result,
    }


# ── Main ───────────────────────────────────────────────────────────────────────

async def main(findings_path: Path) -> None:
    if not findings_path.exists():
        log.error("Findings file not found: %s", findings_path)
        sys.exit(1)

    data = json.loads(findings_path.read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data

    successful = [f for f in findings if f.get("success")]
    log.info(
        "Loaded %d total findings, %d successful exploits to patch",
        len(findings), len(successful),
    )

    if not successful:
        log.info("No successful exploits — nothing for the blue team to do.")
        return

    # Connect to GitHub
    gh = Github(GITHUB_TOKEN)
    try:
        gh_repo = gh.get_repo(GITHUB_REPO)
        log.info("Connected to GitHub repo: %s", gh_repo.full_name)
    except Exception as exc:
        log.error("Cannot connect to GitHub repo %s: %s", GITHUB_REPO, exc)
        sys.exit(1)

    # Deduplicate: one agent per unique (type, target) pair
    seen: set[str] = set()
    deduped: list[dict] = []
    for f in successful:
        key = f"{f.get('type', '')}:{f.get('target', '')}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    log.info("Spawning %d blue-team agents (deduplicated by type+target)", len(deduped))

    # Run agents concurrently
    tasks = [_run_agent(f, gh_repo) for f in deduped]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    pr_records = []
    for r in results:
        if isinstance(r, Exception):
            log.error("Agent raised exception: %s", r)
            pr_records.append({"success": False, "error": str(r)})
        else:
            pr_records.append(r)

    # Write PR log
    PRS_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    output = {
        "run_id": data.get("run_id") if isinstance(data, dict) else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_prs_attempted": len(pr_records),
        "total_prs_created": sum(1 for r in pr_records if r.get("success")),
        "prs": pr_records,
    }
    PRS_OUTPUT_PATH.write_text(json.dumps(output, indent=2))

    log.info(
        "Blue team done. %d/%d PRs created. Written to %s",
        output["total_prs_created"],
        output["total_prs_attempted"],
        PRS_OUTPUT_PATH,
    )
    for r in pr_records:
        if r.get("success"):
            log.info("  PR: %s  (%s / %s)", r.get("pr_url"), r.get("finding_type"), r.get("severity"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OpenClaw Blue Team Orchestrator")
    parser.add_argument(
        "--findings",
        type=Path,
        default=FINDINGS_PATH,
        help="Path to findings.json produced by red_team.py",
    )
    args = parser.parse_args()
    asyncio.run(main(args.findings))
