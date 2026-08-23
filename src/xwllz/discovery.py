"""The ASM discovery pipeline: gather -> resolve -> scan -> probe -> detect -> store.

Each phase is isolated so a failure never aborts the run; phases degrade to
pure-Python implementations when optional tools/keys are missing.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from xwllz import db
from xwllz.config import Config
from xwllz.detectors import Finding
from xwllz.engines import dns as dns_engine
from xwllz.engines import http as http_engine
from xwllz.engines import ports as ports_engine
from xwllz.engines import tls as tls_engine
from xwllz.integrations import dnsx_subdomains, nmap_open_ports
from xwllz.sources import crt_sh, keyed

DEFAULT_WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "ssh", "api", "app",
    "dev", "stage", "staging", "test", "beta", "admin", "portal", "vpn", "remote",
    "git", "gitlab", "jenkins", "ci", "grafana", "kibana", "jira", "confluence",
    "status", "metrics", "monitor", "dash", "dashboard", "internal", "intranet",
    "lb", "proxy", "cdn", "static", "assets", "media", "img", "uploads", "files",
    "blog", "docs", "support", "help", "login", "auth", "sso", "oauth", "billing",
    "shop", "store", "pay", "checkout", "gateway", "payment",
]


@dataclass
class PhaseStats:
    subdomains: int = 0
    hosts_resolved: int = 0
    open_ports: int = 0
    services_probed: int = 0
    findings: int = 0


@dataclass
class Org:
    id: int
    name: str
    domains: list[str]


def load_org(conn, name: str) -> Org:
    row = conn.execute("SELECT * FROM orgs WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise KeyError(f"org '{name}' not found — run 'xwllz init {name} --domains …' first")
    return Org(id=int(row["id"]), name=row["name"], domains=[d.strip() for d in row["domains"].split(",") if d.strip()])


# ---------------------------------------------------------------- phases

async def gather_hosts(org: Org, cfg: Config, passive_only: bool = False) -> set[str]:
    """Return all candidate hostnames: roots + crt.sh + keyed sources (+ dnsx brute)."""
    roots = {d.lower().rstrip(".") for d in org.domains}
    all_hosts: set[str] = set(roots)

    async with httpx.AsyncClient() as shared:
        crt_jobs = [crt_sh.fetch_subdomains(d, shared) for d in roots]
        # Keyed sources are passive (subdomain listings); always run them.
        keyed_jobs = [keyed.subdomain_sources(cfg, d) for d in roots]
        crt_results, keyed_results = await asyncio.gather(
            asyncio.gather(*crt_jobs), asyncio.gather(*keyed_jobs)
        )

    for batch in crt_results:
        all_hosts.update(batch)
    for batch in keyed_results:
        all_hosts.update(batch)

    if not passive_only:
        for root in roots:
            if brute := await _brute(root, cfg):
                all_hosts.update(brute)

    return all_hosts


async def _brute(root: str, cfg: Config) -> set[str]:
    """Subdomain brute via dnsx when available (pure-Python brute not worth it)."""
    return await dnsx_subdomains(root, cfg, DEFAULT_WORDLIST) or set()


async def resolve_hosts(hosts: set[str], cfg: Config) -> dict[str, list[str]]:
    """Resolve each host to IPs. Returns {host: [ips]} for hosts that resolve."""
    resolved: dict[str, list[str]] = {}
    sem = asyncio.Semaphore(cfg.max_workers)

    async def one(host: str) -> tuple[str, list[str]]:
        async with sem:
            try:
                return host, await asyncio.get_running_loop().run_in_executor(
                    None, dns_engine.resolve_ips, host, cfg.dns_timeout
                )
            except Exception:  # noqa: BLE001 - never abort the run
                return host, []

    results = await asyncio.gather(*(one(h) for h in sorted(hosts)))
    for host, ips in results:
        if ips:
            resolved[host] = ips
    return resolved


async def scan_ports(
    hosts: set[str],
    cfg: Config,
    ports: list[int] | None = None,
    use_nmap: bool = True,
) -> dict[str, list[int]]:
    """Port-scan hosts. Uses nmap if available and requested, else pure-Python async scan."""
    open_ports: dict[str, list[int]] = {}
    for host in sorted(hosts):
        if use_nmap:
            nmap_result = await nmap_open_ports(host, cfg)
            if nmap_result is not None:
                open_ports[host] = nmap_result
                continue
        host_ports = await ports_engine.scan_host(
            host, ports=ports, concurrency=cfg.port_scan_concurrency
        )
        if host_ports:
            open_ports[host] = host_ports
    return open_ports


async def probe_services(
    open_ports: dict[str, list[int]],
    cfg: Config,
    probe_http: bool = True,
) -> tuple[dict[tuple[str, int], http_engine.HttpResult], dict[tuple[str, int], tls_engine.TlsResult]]:
    """Probe HTTP(S) and TLS for each open port."""
    http_results: dict[tuple[str, int], http_engine.HttpResult] = {}
    tls_results: dict[tuple[str, int], tls_engine.TlsResult] = {}

    http_targets: list[tuple[str, int]] = []
    tls_targets: list[tuple[str, int]] = []
    for host, plist in open_ports.items():
        for port in plist:
            http_targets.append((host, port))
            # Probe TLS on standard TLS ports, plus any port that responded https.
            if port in (443, 8443):
                tls_targets.append((host, port))

    if probe_http and http_targets:
        sem = asyncio.Semaphore(cfg.max_workers)

        async def probe_http(pair: tuple[str, int]) -> tuple[tuple[str, int], http_engine.HttpResult]:
            async with sem:
                return pair, await http_engine.probe(pair[0], pair[1], cfg.http_timeout)

        for pair, result in await asyncio.gather(*(probe_http(p) for p in http_targets)):
            http_results[pair] = result

    if tls_targets:
        results = await tls_engine.fetch_many(tls_targets, max_workers=cfg.max_workers)
        tls_results.update(results)

    return http_results, tls_results


# ---------------------------------------------------------------- store

def _service_name(port: int, http: http_engine.HttpResult | None, tls: tls_engine.TlsResult | None) -> str | None:
    if http is not None and http.status is not None:
        return "http" if http.scheme == "http" else "https"
    return {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 3306: "mysql", 5432: "postgresql"}.get(port)


def store_results(
    conn,
    org: Org,
    resolved: dict[str, list[str]],
    open_ports: dict[str, list[int]],
    http_results: dict[tuple[str, int], http_engine.HttpResult],
    tls_results: dict[tuple[str, int], tls_engine.TlsResult],
    extra_findings: dict[tuple[str, int], list[Finding]] | None = None,
) -> PhaseStats:
    """Upsert assets, services, and findings from a discovery run."""
    stats = PhaseStats()
    extra_findings = extra_findings or {}

    for host in resolved:
        db.upsert_asset(conn, org.id, host, "subdomain" if "." in host else "domain", "dns")

    seen_assets: set[int] = set()
    for host, ports in open_ports.items():
        asset_id = db.upsert_asset(conn, org.id, host, "subdomain" if "." in host else "domain", "scan")
        seen_assets.add(asset_id)
        stats.open_ports += len(ports)
        for port in ports:
            http = http_results.get((host, port))
            tls = tls_results.get((host, port))
            service = _service_name(port, http, tls)
            tls_expiry = tls.not_after.isoformat() if tls and tls.not_after else None
            tech = ",".join(http.tech) if http and http.tech else None
            banner = http.server if http and http.server else (tls.issuer if tls else None)
            service_id = db.upsert_service(
                conn,
                asset_id,
                port,
                "tcp",
                service=service,
                banner=banner,
                tech=tech,
                tls_expires=tls_expiry,
                http_title=(http.title if http else None),
                http_status=(http.status if http else None),
            )
            stats.services_probed += 1

            # Detectors
            findings: list[Finding] = []
            if tls and not tls.error:
                findings += detectors_tls(tls, host)
            if http and http.status is not None:
                findings += detectors_http(http)
            findings += detectors_ports([port])
            findings += extra_findings.get((host, port), [])
            for f in findings:
                db.upsert_finding(
                    conn, org.id, f.severity, f.kind, f.title, f.detail,
                    source="detector", asset_id=asset_id, service_id=service_id,
                )
                stats.findings += 1
    return stats


def detectors_tls(tls: tls_engine.TlsResult, host: str) -> list[Finding]:
    from xwllz import detectors
    return detectors.tls_expiry(tls) + detectors.tls_hostname_mismatch(tls, host)


def detectors_http(http: http_engine.HttpResult) -> list[Finding]:
    from xwllz import detectors
    return detectors.security_headers(http)


def detectors_ports(ports: list[int]) -> list[Finding]:
    from xwllz import detectors
    return detectors.exposed_ports(ports)


def snapshot(conn, org: Org) -> int:
    """Record a snapshot row; returns its id."""
    counts = conn.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM assets WHERE org_id = ? AND status = 'active'),
            (SELECT COUNT(*) FROM services s JOIN assets a ON s.asset_id = a.id
                 WHERE a.org_id = ? AND a.status = 'active'),
            (SELECT COUNT(*) FROM findings WHERE org_id = ?)
        """,
        (org.id, org.id, org.id),
    ).fetchone()
    cur = conn.execute(
        "INSERT INTO snapshots (org_id, assets, services, findings) VALUES (?, ?, ?, ?)",
        (org.id, int(counts[0]), int(counts[1]), int(counts[2])),
    )
    conn.commit()
    return int(cur.lastrowid)


def diff_snapshots(conn, org: Org, snapshot_id: int) -> dict:
    """Compare the latest two snapshots and report asset/finding deltas."""
    rows = conn.execute(
        "SELECT * FROM snapshots WHERE org_id = ? ORDER BY id DESC LIMIT 2", (org.id,)
    ).fetchall()
    if len(rows) < 2:
        return {}
    prev, new = rows[1], rows[0]
    out = {
        "assets": {"prev": int(prev["assets"]), "new": int(new["assets"])},
        "services": {"prev": int(prev["services"]), "new": int(new["services"])},
        "findings": {"prev": int(prev["findings"]), "new": int(new["findings"])},
    }
    out["assets_delta"] = out["assets"]["new"] - out["assets"]["prev"]
    out["findings_delta"] = out["findings"]["new"] - out["findings"]["prev"]
    return out


async def run_discovery(conn, org: Org, cfg: Config, *, passive_only: bool = False, ports: list[int] | None = None, use_nmap: bool = True) -> PhaseStats:
    """Run the full discovery pipeline for an org."""
    hosts = await gather_hosts(org, cfg, passive_only)
    resolved = await resolve_hosts(hosts, cfg)

    # email posture findings for root domains (SPF/DMARC/DKIM)
    posture_findings = 0
    for root in org.domains:
        try:
            posture = await asyncio.get_running_loop().run_in_executor(
                None, dns_engine.check_posture, root, cfg.dns_timeout
            )
            for f in detectors_email(posture):
                db.upsert_finding(conn, org.id, f.severity, f.kind, f.title, f.detail, source="detector")
                posture_findings += 1
        except Exception:  # noqa: BLE001, S112 - never abort the run
            continue

    if passive_only:
        for host in resolved:
            db.upsert_asset(conn, org.id, host, "subdomain" if "." in host else "domain", "dns")
        stats = PhaseStats(subdomains=len(hosts), hosts_resolved=len(resolved), findings=posture_findings)
        snapshot(conn, org)
        return stats

    open_ports = await scan_ports(set(resolved), cfg, ports=ports, use_nmap=use_nmap)
    http_results, tls_results = await probe_services(open_ports, cfg)

    stats = store_results(conn, org, resolved, open_ports, http_results, tls_results)
    stats.subdomains = len(hosts)
    stats.hosts_resolved = len(resolved)
    stats.findings += posture_findings
    snapshot(conn, org)
    return stats


def detectors_email(posture: dns_engine.DnsResult) -> list[Finding]:
    from xwllz import detectors
    return detectors.email_posture(posture)