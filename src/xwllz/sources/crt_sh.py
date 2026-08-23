"""Subdomain enumeration via certificate transparency (crt.sh). Keyless."""

from __future__ import annotations

import json

import httpx

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


async def fetch_subdomains(domain: str, client: httpx.AsyncClient, timeout: float = 20.0) -> set[str]:
    """Return the set of subdomains found in crt.sh for a domain."""
    url = CRTSH_URL.format(domain=domain)
    try:
        resp = await client.get(url, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
        records = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError, ValueError):
        return set()

    names: set[str] = set()
    for rec in records:
        name = rec.get("name_value", "")
        for entry in name.split("\n"):
            entry = entry.strip().lower().rstrip(".")
            if entry and "*" not in entry and entry.endswith(f".{domain.lower()}"):
                names.add(entry)
    return names


async def run(domain: str, timeout: float = 20.0) -> set[str]:
    async with httpx.AsyncClient() as client:
        return await fetch_subdomains(domain, client, timeout)