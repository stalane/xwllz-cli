"""Report rendering: markdown, JSON, and HTML views of an org's surface."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone


def _rows(conn, query: str, params: tuple = ()) -> list[sqlite3.Row]:
    return conn.execute(query, params).fetchall()


def render(conn, org_name: str, fmt: str = "md") -> str:
    org = conn.execute("SELECT * FROM orgs WHERE name = ?", (org_name,)).fetchone()
    if org is None:
        raise KeyError(f"org '{org_name}' not found")

    assets = _rows(
        conn,
        "SELECT * FROM assets WHERE org_id = ? AND status = 'active' ORDER BY host",
        (org["id"],),
    )
    findings = _rows(
        conn,
        """SELECT f.*, a.host, s.port
           FROM findings f
           LEFT JOIN assets a ON f.asset_id = a.id
           LEFT JOIN services s ON f.service_id = s.id
           WHERE f.org_id = ? ORDER BY
             CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
             f.title""",
        (org["id"],),
    )
    services = _rows(
        conn,
        """SELECT s.*, a.host FROM services s
           JOIN assets a ON s.asset_id = a.id
           WHERE a.org_id = ? AND a.status = 'active'
           ORDER BY a.host, s.port""",
        (org["id"],),
    )
    snapshots = _rows(
        conn,
        "SELECT * FROM snapshots WHERE org_id = ? ORDER BY id DESC LIMIT 1",
        (org["id"],),
    )
    last = snapshots[0] if snapshots else None

    if fmt == "json":
        return _render_json(org, assets, findings, services, last)
    if fmt == "html":
        return _render_html(org, assets, findings, services, last)
    return _render_md(org, assets, findings, services, last)


def _render_md(org, assets, findings, services, last) -> str:
    lines: list[str] = []
    lines.append(f"# xwllz report — {org['name']}")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append(f"Scope: `{org['domains']}`")
    if last:
        lines.append(
            f"Surface: **{last['assets']}** assets · **{last['services']}** services · "
            f"**{last['findings']}** findings"
        )
    lines.append("")

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in ("high", "medium", "low", "info"):
        if sev in by_sev:
            lines.append(f"| {sev} | {by_sev[sev]} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("_No findings recorded._")
    for f in findings:
        host = f["host"] or ""
        port = f" :{f['port']}" if f["port"] else ""
        lines.append(f"- **[{f['severity'].upper()}]** {f['title']} — {host}{port}")
        if f["detail"]:
            lines.append(f"  - {f['detail']}")
    lines.append("")

    lines.append("## Services")
    lines.append("")
    if not services:
        lines.append("_No services recorded._")
    for s in services:
        meta = []
        if s["service"]:
            meta.append(s["service"])
        if s["http_title"]:
            meta.append(s["http_title"])
        if s["tech"]:
            meta.append(f"tech: {s['tech']}")
        suffix = f" ({', '.join(meta)})" if meta else ""
        lines.append(f"- `{s['host']}:{s['port']}`{suffix}")
    lines.append("")

    lines.append("## Assets")
    lines.append("")
    for a in assets:
        lines.append(f"- `{a['host']}` ({a['type']}, {a['source'] or '?'})")

    return "\n".join(lines) + "\n"


def _render_json(org, assets, findings, services, last) -> str:
    payload = {
        "org": dict(org),
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "surface": {"assets": len(assets), "services": len(services), "findings": len(findings)},
        "last_snapshot": dict(last) if last else None,
        "assets": [dict(a) for a in assets],
        "services": [dict(s) for s in services],
        "findings": [dict(f) for f in findings],
    }
    return json.dumps(payload, indent=2, default=str)


def _render_html(org, assets, findings, services, last) -> str:
    md = _render_md(org, assets, findings, services, last)
    import html as html_mod

    body = html_mod.escape(md).replace("\n", "<br>")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>xwllz report — {html_mod.escape(org['name'])}</title>
<style>
body{{font-family:-apple-system,system-ui,sans-serif;color:#e0e6ed;background:#050506;max-width:900px;margin:0 auto;padding:2rem}}
a{{color:#4a90e2}}
</style></head><body><pre>{body}</pre></body></html>\n"""