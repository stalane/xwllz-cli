"""Keyed API source wrappers. Each returns None when its key is missing so the
pipeline can skip gracefully. All calls are made over httpx.
"""

from __future__ import annotations

import asyncio
import json

import httpx

from xwllz.config import Config


class _KeyedSource:
    """Base: resolves config keys, provides an async client helper."""

    key_name: str = ""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.key = cfg.keys.get(self.key_name)

    @property
    def enabled(self) -> bool:
        return bool(self.key)

    async def _get_json(self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 15.0) -> dict | list | None:
        if not self.enabled:
            return None
        h = {"Accept": "application/json"}
        if headers:
            h.update(headers)
        try:
            async with httpx.AsyncClient(timeout=timeout, headers=h) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                return resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None


class ShodanSource(_KeyedSource):
    """Shodan host + DNS lookup. Env: SHODAN_API_KEY."""

    key_name = "shodan"

    async def host(self, ip: str) -> dict | None:
        data = await self._get_json(
            f"https://api.shodan.io/shodan/host/{ip}?key={self.key}"
        )
        return data if isinstance(data, dict) else None

    async def domain_subdomains(self, domain: str) -> list[str] | None:
        data = await self._get_json(
            f"https://api.shodan.io/dns/domain/{domain}?key={self.key}"
        )
        if not isinstance(data, dict):
            return None
        return [e.get("subdomain", "") for e in data.get("data", []) if e.get("subdomain")]


class SecurityTrailsSource(_KeyedSource):
    """SecurityTrails subdomains. Env: SECURITYTRAILS_API_KEY."""

    key_name = "securitytrails"

    async def subdomains(self, domain: str) -> list[str] | None:
        data = await self._get_json(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": self.key or ""},
        )
        if not isinstance(data, dict):
            return None
        subs = data.get("subdomains", [])
        return [f"{s}.{domain}" for s in subs if isinstance(s, str)]


class CensysSource(_KeyedSource):
    """Censys search. Env: CENSYS_API_ID + CENSYS_API_SECRET."""

    key_name = "censys"

    def __init__(self, cfg: Config) -> None:
        super().__init__(cfg)
        self.secret = cfg.keys.get("censys_secret")

    @property
    def enabled(self) -> bool:
        return bool(self.key and self.secret)

    async def _get_json(self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 15.0) -> dict | list | None:
        if not self.enabled:
            return None
        h = {"Accept": "application/json"}
        if headers:
            h.update(headers)
        try:
            async with httpx.AsyncClient(timeout=timeout, headers=h, auth=(self.key, self.secret)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                return resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

    async def search_certificates(self, domain: str, max_hits: int = 100) -> list[str] | None:
        payload = {"q": f"names: {domain}", "per_page": min(max_hits, 100)}
        try:
            async with httpx.AsyncClient(timeout=15.0, auth=(self.key, self.secret)) as client:
                resp = await client.post("https://search.censys.io/api/v2/certificates/search", json=payload)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        names: set[str] = set()
        for hit in data.get("result", {}).get("hits", []) or []:
            for name in (hit.get("names") or []):
                name = str(name).lower().rstrip(".")
                if name.endswith(f".{domain.lower()}") or name == domain.lower():
                    names.add(name)
        return sorted(names) or None


class URLhausSource(_KeyedSource):
    """URLhaus blacklist lookup. Env: URLHAUS_API_KEY (free)."""

    key_name = "urlhaus"

    async def lookup(self, indicator: str, type_: str) -> dict | None:
        # Only domain/url lookups supported here.
        if type_ not in ("url", "domain"):
            return None
        key = "url" if type_ == "url" else "host"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={key: indicator},
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError:
            return None


class UrlscanSource(_KeyedSource):
    """urlscan.io submit + result. Env: URL_SCAN_API_KEY."""

    key_name = "urlscan"

    async def scan(self, url: str) -> dict | None:
        if not self.enabled:
            return None
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    "https://urlscan.io/api/v1/scan/",
                    json={"url": url},
                    headers={"API-Key": self.key or "", "Content-Type": "application/json"},
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError:
            return None


class VirusTotalSource(_KeyedSource):
    """VirusTotal indicator lookup. Env: VIRUSTOTAL_API_KEY."""

    key_name = "virustotal"

    async def lookup(self, indicator: str, type_: str) -> dict | None:
        if not self.enabled:
            return None
        endpoint = {
            "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            "url": f"https://www.virustotal.com/api/v3/urls/{indicator}",
        }.get(type_)
        if not endpoint:
            return None
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(endpoint, headers={"x-apikey": self.key or ""})
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError:
            return None


async def subdomain_sources(cfg: Config, domain: str) -> set[str]:
    """Aggregate subdomains from all keyed sources, skipping missing keys."""
    found: set[str] = set()
    jobs = [
        ShodanSource(cfg).domain_subdomains(domain),
        SecurityTrailsSource(cfg).subdomains(domain),
        CensysSource(cfg).search_certificates(domain),
    ]
    results = await asyncio.gather(*jobs)
    for batch in results:
        if batch:
            found.update(batch)
    return found