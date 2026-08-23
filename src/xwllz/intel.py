"""Indicator lookups: URLhaus (keyless), urlscan, VirusTotal, Shodan (keyed)."""

from __future__ import annotations

import json
import sqlite3

from xwllz.config import Config
from xwllz.sources.keyed import (
    ShodanSource,
    URLhausSource,
    VirusTotalSource,
)


def _classify_indicator(indicator: str) -> str:
    indicator = indicator.strip().lower()
    if indicator.startswith(("http://", "https://", "www.")):
        return "url"
    if indicator.replace(".", "").isdigit():
        return "ip"
    return "domain"


async def lookup(
    indicator: str,
    cfg: Config,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Run lookups across enabled sources; cache in intel table when a conn is given."""
    type_ = _classify_indicator(indicator)
    results: dict[str, dict] = {}

    urlhaus = URLhausSource(cfg)
    if urlhaus.enabled or type_ in ("url", "domain"):
        data = await urlhaus.lookup(indicator, type_)
        if data:
            results["urlhaus"] = {"query_status": data.get("query_status"), "data": data}

    vt = VirusTotalSource(cfg)
    if vt.enabled:
        data = await vt.lookup(indicator, type_)
        if data:
            stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {})
            results["virustotal"] = {"stats": stats, "data": data}

    shodan = ShodanSource(cfg)
    if shodan.enabled and type_ == "ip":
        data = await shodan.host(indicator)
        if data:
            results["shodan"] = {"ports": data.get("ports"), "org": data.get("org"), "data": data}

    if conn is not None:
        for source, payload in results.items():
            conn.execute(
                """INSERT INTO intel (indicator, type, verdict, source, data)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(indicator, type, source) DO UPDATE SET data = excluded.data,
                       verdict = excluded.verdict, checked_at = datetime('now')""",
                (indicator, type_, _verdict(payload), source, json.dumps(payload, default=str)),
            )
        conn.commit()

    return results


def _verdict(payload: dict) -> str:
    data = payload.get("data") or {}
    if isinstance(data, dict) and data.get("query_status") == "offline":
        return "malicious"
    stats = payload.get("stats")
    if stats:
        if stats.get("malicious", 0) > 0:
            return "malicious"
        if stats.get("suspicious", 0) > 0:
            return "suspicious"
        return "clean"
    return "unknown"


async def run_lookup(indicator: str, cfg: Config, conn=None) -> dict:
    return await lookup(indicator, cfg, conn)