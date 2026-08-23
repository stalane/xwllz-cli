"""Optional integrations with installed binaries (auto-detected, graceful fallback).

Every function returns the same shape its pure-Python counterpart would, so the
pipeline can swap implementations based on what is on PATH. All functions are
guarded: if the tool is missing or fails, they return a "not used" sentinel and
the caller falls back to the pure-Python path.
"""

from __future__ import annotations

import asyncio
import re

from xwllz.config import Config

NOT_USED = None


def _run(cmd: list[str], timeout: float) -> tuple[int, str]:
    """Run a command; return (exitcode, stdout). Async wrapper used by callers."""
    proc = asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return proc


async def nmap_open_ports(
    host: str,
    cfg: Config,
    ports: str = "top-1000",
    timeout: float = 180.0,
) -> list[int] | None:
    """Use nmap for a port scan; returns open ports or None (fallback to Python scan)."""
    binary = cfg.tool("nmap")
    if not binary:
        return None
    cmd = [binary, "-Pn", "-T4", "--open", "-p", ports, "-oG", "-", host]
    proc = await _run(cmd, timeout)
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return None
    if proc.returncode != 0:
        return None
    ports_found: list[int] = []
    for line in stdout.decode(errors="ignore").splitlines():
        m = re.search(r"Ports:\s+(.+)", line)
        if not m:
            continue
        for part in m.group(1).split(","):
            p = part.strip().split("/")[0]
            state = part.strip().split("/")[1] if "/" in part else ""
            if p.isdigit() and state == "open":
                ports_found.append(int(p))
    return sorted(ports_found)


async def nuclei_scan(
    host: str,
    cfg: Config,
    timeout: float = 300.0,
) -> list[dict[str, str]] | None:
    """Run nuclei against a host; returns list of findings or None to skip."""
    binary = cfg.tool("nuclei")
    if not binary:
        return None
    cmd = [binary, "-target", host, "-silent", "-json"]
    proc = await _run(cmd, timeout)
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return None
    findings: list[dict[str, str]] = []
    for line in stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            import json

            item = json.loads(line)
            findings.append(
                {
                    "title": item.get("info", {}).get("name", "nuclei finding"),
                    "severity": item.get("info", {}).get("severity", "info"),
                    "detail": item.get("matched-at", ""),
                }
            )
        except json.JSONDecodeError:
            continue
    return findings or None


async def dnsx_subdomains(
    domain: str,
    cfg: Config,
    wordlist: list[str] | None = None,
    timeout: float = 120.0,
) -> set[str] | None:
    """Use dnsx to resolve subdomains from a wordlist; None -> use pure-Python brute."""
    binary = cfg.tool("dnsx")
    if not binary or not wordlist:
        return None
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".txt") as fh:
        for word in wordlist:
            fh.write(f"{word}.{domain}\n")
        fh.flush()
        cmd = [binary, "-silent", "-l", fh.name]
        proc = await _run(cmd, timeout)
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return None
    if proc.returncode != 0:
        return None
    resolved = {line.strip().lower().rstrip(".") for line in stdout.decode(errors="ignore").splitlines() if line.strip()}
    return {h for h in resolved if h.endswith(f".{domain.lower()}")} or None