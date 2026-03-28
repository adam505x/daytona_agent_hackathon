"""
blue_team.py — OpenClaw Blue Team Orchestrator

Reads findings.json produced by the red team, spawns one Claude agent per
successful exploit finding, and each agent opens a GitHub PR with a patch.

ARCHITECTURE:
  OpenClaw (Node.js gateway)
      └─ instructs agent via SKILL.md
          └─ agent calls exec("python3 orchestrator/blue_team.py")
              └─ this script calls the Anthropic API (raw tool_use, no frameworks)
                  └─ each agent has two tools:
                       read_file(path)  — reads source from TARGET_REPO_PATH
                       create_pr(...)   — opens a GitHub PR via PyGithub

CREDENTIAL FLOW (Jentic Mini):
  ANTHROPIC_API_KEY and GITHUB_TOKEN are stored in Jentic Mini's encrypted vault.
  When running inside the OpenClaw + Jentic Mini stack they are injected into
  the environment at runtime — this script never handles raw credentials directly.

Usage:
  python3 orchestrator/blue_team.py [--findings path/to/findings.json]
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
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
GITHUB_TOKEN      = os.environ["GITHUB_TOKEN"]
GITHUB_REPO       = os.environ["GITHUB_REPO"]
TARGET_REPO_PATH  = Path(os.getenv("TARGET_REPO_PATH", "."))

# claude-sonnet-4-6 is the current Sonnet 4.6 model
# Override with BLUE_TEAM_MODEL env var if needed
MODEL             = os.getenv("BLUE_TEAM_MODEL", "claude-sonnet-4-6")
MAX_AGENT_TURNS   = 12

FINDINGS_PATH   = Path(__file__).parent.parent / "output" / "findings.json"
PRS_OUTPUT_PATH = Path(__file__).parent.parent / "output" / "prs.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("blue_team")

# ── Tool schemas (Anthropic tool_use format) ──────────────────────────────────

TOOLS = [
    {
        "name": "read_file",
        "description": (
            "Read a source file from the target repository. "
            "Use this to understand the vulnerable code before writing a patch. "
            "Path must be relative to the repository root (e.g. 'target/app.py')."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path within the repository (e.g. 'target/app.py')",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "create_pr",
        "description": (
            "Create a GitHub Pull Request containing one or more patched files. "
            "Call this exactly once when you have a complete, correct fix. "
            "Provide the FULL new file contents, not a diff."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "branch": {
                    "type": "string",
                    "description": "Branch name (e.g. 'fix/sqli-inventory-sort')",
                },
                "files_changed": {
                    "type": "array",
                    "description": "Files to patch",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path":    {"type": "string", "description": "Relative file path"},
                            "content": {"type": "string", "description": "Full new file content after patch"},
                        },
                        "required": ["path", "content"],
                    },
                },
                "description": {
                    "type": "string",
                    "description": "PR description: vulnerability class, root cause, and fix explanation",
                },
            },
            "required": ["branch", "files_changed", "description"],
        },
    },
]


# ── Tool implementations ───────────────────────────────────────────────────────

def _tool_read_file(path: str) -> str:
    """
    Read a file from the target repository.

    Path is sandboxed to TARGET_REPO_PATH — absolute paths and directory
    traversal are blocked so the agent can't read files outside the repo.
    """
    repo_root = TARGET_REPO_PATH.resolve()
    try:
        # Resolve the full path and verify it stays inside the repo root
        target = (repo_root / path).resolve()
        if not str(target).startswith(str(repo_root)):
            return "ERROR: Access denied — path is outside the repository root."
        if not target.exists():
            # List the directory contents to help the agent navigate
            parent = target.parent
            if parent.exists():
                listing = "\n".join(str(f.relative_to(repo_root)) for f in parent.iterdir())
                return f"ERROR: File not found: {path}\n\nContents of {parent.relative_to(repo_root)}:\n{listing}"
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
    """
    Create a GitHub PR with the patched files.

    Creates a new branch off the default branch, commits each file change,
    then opens a PR with the finding ID and description in the body.
    """
    # Sanitise branch name to prevent any injection via agent output
    safe_branch = re.sub(r"[^a-zA-Z0-9._/-]", "-", branch)[:80]
    if not safe_branch.startswith(("fix/", "patch/", "security/")):
        safe_branch = f"fix/{safe_branch}"

    log.info("Creating PR on branch '%s' with %d file(s)", safe_branch, len(files_changed))

    try:
        default_branch = gh_repo.default_branch
        base_sha       = gh_repo.get_branch(default_branch).commit.sha

        # Create the new branch for this fix
        try:
            gh_repo.create_git_ref(ref=f"refs/heads/{safe_branch}", sha=base_sha)
        except GithubException as e:
            if e.status == 422:
                # Branch already exists — append a short random suffix
                safe_branch = f"{safe_branch}-{uuid.uuid4().hex[:6]}"
                gh_repo.create_git_ref(ref=f"refs/heads/{safe_branch}", sha=base_sha)
            else:
                raise

        # Commit each patched file to the new branch
        for file_patch in files_changed:
            file_path   = file_patch["path"]
            new_content = file_patch["content"]
            commit_msg  = f"security: patch {file_path} — finding {finding_id}"

            try:
                existing = gh_repo.get_contents(file_path, ref=safe_branch)
                gh_repo.update_file(
                    path=file_path, message=commit_msg,
                    content=new_content, sha=existing.sha, branch=safe_branch,
                )
            except GithubException:
                # File doesn't exist yet — create it
                gh_repo.create_file(
                    path=file_path, message=commit_msg,
                    content=new_content, branch=safe_branch,
                )

        # Open the PR
        pr_body = (
            f"## Automated Security Fix\n\n"
            f"**Finding ID:** `{finding_id}`\n\n"
            f"{description}\n\n"
            f"---\n"
            f"*Generated by OpenClaw Blue Team Orchestrator*"
        )
        pr = gh_repo.create_pull(
            title=f"[Security] Automated patch — finding {finding_id}",
            body=pr_body,
            head=safe_branch,
            base=default_branch,
        )
        log.info("PR created: %s", pr.html_url)
        return {"success": True, "pr_url": pr.html_url, "pr_number": pr.number}

    except Exception as exc:
        log.error("PR creation failed: %s", exc)
        return {"success": False, "error": str(exc)}


# ── Agent system prompt ────────────────────────────────────────────────────────

def _system_prompt(finding: dict) -> str:
    return f"""You are a senior application-security engineer on the blue team.
You have received a confirmed vulnerability finding from an automated red team scan.

Your task:
1. Use read_file to read the vulnerable source file(s) from the repository.
2. Identify the exact line(s) where the vulnerability exists.
3. Write a minimal, correct patch — change only what is necessary to fix the vulnerability.
4. Call create_pr exactly once with the full patched file content and a clear description.

Do not refactor unrelated code. Do not add logging, comments, or docstrings beyond what
is needed. Do not add error handling for scenarios that cannot happen. Be surgical.

Vulnerability finding:
{json.dumps(finding, indent=2)}

Common fix patterns for the vulnerabilities in this system:
- ORDER BY injection: use a whitelist map of allowed sort columns; never interpolate sort_col directly
- os.path.join absolute-path bypass: check that the resolved path starts with the base directory after join()
- subprocess command injection: use a list of arguments instead of a shell string, or set shell=False

The main application file is at: target/app.py
"""


# ── Agent loop ─────────────────────────────────────────────────────────────────

async def _run_agent(finding: dict, gh_repo: Any) -> dict:
    """
    Run a single blue-team Claude agent for one finding.

    The agent calls read_file repeatedly to understand the code,
    then calls create_pr exactly once when it has a complete fix.
    Returns a dict with success, pr_url, and finding metadata.
    """
    finding_id = finding.get("id", str(uuid.uuid4())[:8])
    log.info("Agent starting for finding %s (type=%s severity=%s)",
             finding_id[:8], finding.get("type"), finding.get("severity"))

    client   = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    messages: list[dict] = []
    pr_result: dict = {"success": False, "error": "agent did not call create_pr"}

    # Seed the conversation — this is the agent's first instruction
    messages.append({
        "role": "user",
        "content": (
            f"Please analyse finding {finding_id[:8]} and open a PR with a patch. "
            f"Start by reading target/app.py."
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

        # Append the assistant's response to maintain conversation history
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            log.info("Agent %s finished naturally after %d turns", finding_id[:8], turn + 1)
            break

        if response.stop_reason != "tool_use":
            log.warning("Unexpected stop_reason '%s' for %s", response.stop_reason, finding_id[:8])
            break

        # Process every tool_use block in this response
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue

            tool_name  = block.name
            tool_input = block.input
            tool_use_id = block.id

            if tool_name == "read_file":
                # Read the requested file and return its content to the agent
                content = _tool_read_file(tool_input["path"])
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": tool_use_id,
                    "content":     content,
                })

            elif tool_name == "create_pr":
                # Agent is ready to open the PR — execute it and stop the loop
                pr_result = _tool_create_pr(
                    branch         = tool_input["branch"],
                    files_changed  = tool_input["files_changed"],
                    description    = tool_input["description"],
                    finding_id     = finding_id,
                    gh_repo        = gh_repo,
                )
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": tool_use_id,
                    "content":     json.dumps(pr_result),
                })
                # Return immediately — PR is created, no more turns needed
                messages.append({"role": "user", "content": tool_results})
                return {
                    "finding_id":   finding_id,
                    "finding_type": finding.get("type"),
                    "severity":     finding.get("severity"),
                    "target":       finding.get("target"),
                    **pr_result,
                }

            else:
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": tool_use_id,
                    "content":     f"ERROR: Unknown tool '{tool_name}'",
                    "is_error":    True,
                })

        if tool_results:
            messages.append({"role": "user", "content": tool_results})

    # Agent exhausted its turn budget without calling create_pr
    log.warning("Agent %s exhausted %d turns without creating a PR", finding_id[:8], MAX_AGENT_TURNS)
    return {
        "finding_id":   finding_id,
        "finding_type": finding.get("type"),
        "severity":     finding.get("severity"),
        "target":       finding.get("target"),
        **pr_result,
    }


# ── Main ───────────────────────────────────────────────────────────────────────

async def main(findings_path: Path) -> None:
    if not findings_path.exists():
        log.error("Findings file not found: %s", findings_path)
        sys.exit(1)

    data     = json.loads(findings_path.read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data

    successful = [f for f in findings if f.get("success")]
    log.info("Loaded %d findings, %d successful exploits to patch",
             len(findings), len(successful))

    if not successful:
        log.info("No successful exploits — nothing for the blue team to do.")
        return

    # Connect to GitHub
    gh = Github(GITHUB_TOKEN)
    try:
        gh_repo = gh.get_repo(GITHUB_REPO)
        log.info("Connected to GitHub repo: %s", gh_repo.full_name)
    except Exception as exc:
        log.error("Cannot connect to %s: %s", GITHUB_REPO, exc)
        sys.exit(1)

    # Deduplicate by (type, target) so we don't open duplicate PRs
    seen: set[str] = set()
    deduped: list[dict] = []
    for f in successful:
        key = f"{f.get('type', '')}:{f.get('target', '')}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    log.info("Spawning %d blue-team agents (deduplicated)", len(deduped))

    # Run all agents concurrently — one per finding
    tasks   = [_run_agent(f, gh_repo) for f in deduped]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect and write PR results
    pr_records = []
    for r in results:
        if isinstance(r, Exception):
            log.error("Agent raised exception: %s", r)
            pr_records.append({"success": False, "error": str(r)})
        else:
            pr_records.append(r)

    PRS_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    output = {
        "run_id":              data.get("run_id") if isinstance(data, dict) else None,
        "timestamp":           datetime.now(timezone.utc).isoformat(),
        "total_prs_attempted": len(pr_records),
        "total_prs_created":   sum(1 for r in pr_records if r.get("success")),
        "prs":                 pr_records,
    }
    PRS_OUTPUT_PATH.write_text(json.dumps(output, indent=2))

    log.info(
        "Blue team done. %d/%d PRs created → %s",
        output["total_prs_created"], output["total_prs_attempted"], PRS_OUTPUT_PATH,
    )
    for r in pr_records:
        if r.get("success"):
            log.info("  PR: %s  (%s / %s)", r.get("pr_url"), r.get("finding_type"), r.get("severity"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OpenClaw Blue Team Orchestrator")
    parser.add_argument(
        "--findings", type=Path, default=FINDINGS_PATH,
        help="Path to findings.json produced by red_team.py",
    )
    args = parser.parse_args()
    asyncio.run(main(args.findings))
