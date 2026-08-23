"""Discovery pipeline tests — all network functions are mocked; no live calls."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from xwllz import db
from xwllz.config import Config
from xwllz.discovery import (
    Org,
    diff_snapshots,
    gather_hosts,
    run_discovery,
    snapshot,
    store_results,
)
from xwllz.engines import http as http_engine
from xwllz.engines.tls import TlsResult


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(tmp_path / "test.db")
    yield c
    c.close()


@pytest.fixture()
def org(conn):
    conn.execute("INSERT INTO orgs (name, domains) VALUES ('acme', 'example.com')")
    conn.commit()
    return Org(id=db.org_id_by_name(conn, "acme"), name="acme", domains=["example.com"])


@pytest.fixture()
def cfg():
    return Config()


def test_gather_hosts_uses_crtsh(cfg, monkeypatch):
    async def fake_crtsh(domain, client, timeout=20.0):
        return {"www.example.com", "mail.example.com"}

    async def fake_keyed(cfg, domain):
        return {"api.example.com"}

    monkeypatch.setattr("xwllz.sources.crt_sh.fetch_subdomains", fake_crtsh)
    monkeypatch.setattr("xwllz.sources.keyed.subdomain_sources", fake_keyed)

    hosts = asyncio.run(
        gather_hosts(Org(id=1, name="acme", domains=["example.com"]), cfg, passive_only=True)
    )
    assert {"example.com", "www.example.com", "mail.example.com", "api.example.com"} <= hosts


def test_store_results_upserts_and_finds(conn, org):
    resolved = {"www.example.com": ["1.2.3.4"]}
    open_ports = {"www.example.com": [443]}
    http_results = {
        ("www.example.com", 443): http_engine.HttpResult(
            host="www.example.com", port=443, scheme="https", status=200, title="Home", tech=["nginx"]
        )
    }
    tls_results = {
        ("www.example.com", 443): TlsResult(
            host="www.example.com", port=443, days_left=-2,
            not_after=datetime.now(timezone.utc) - timedelta(days=2),
            san=["www.example.com"],
        )
    }

    stats = store_results(conn, org, resolved, open_ports, http_results, tls_results)
    assert stats.services_probed == 1

    svc = conn.execute("SELECT * FROM services").fetchone()
    assert svc["service"] == "https"
    assert svc["http_title"] == "Home"

    findings = conn.execute("SELECT * FROM findings").fetchall()
    kinds = {f["kind"] for f in findings}
    assert kinds >= {"tls_expired", "csp", "hsts"}  # expired cert + missing header findings


def test_snapshot_and_diff(conn, org):
    sid1 = snapshot(conn, org)
    sid2 = snapshot(conn, org)
    assert sid2 > sid1
    diff = diff_snapshots(conn, org, sid2)
    assert diff["assets"]["new"] == diff["assets"]["prev"]


def test_run_discovery_mocked(cfg, conn, org, monkeypatch):
    async def fake_gather(org, cfg, passive_only=False):
        return {"example.com", "www.example.com"}

    async def fake_resolve(hosts, cfg):
        return {"example.com": ["1.2.3.4"], "www.example.com": ["1.2.3.4"]}

    async def fake_scan(hosts, cfg, ports=None, use_nmap=True):
        return {"www.example.com": [8080]}

    async def fake_probe(open_ports, cfg, probe_http=True):
        return {}, {}

    def fake_posture(root, timeout=5.0):
        from xwllz.engines import dns as dns_engine
        return dns_engine.DnsResult(domain=root)

    monkeypatch.setattr("xwllz.discovery.gather_hosts", fake_gather)
    monkeypatch.setattr("xwllz.discovery.resolve_hosts", fake_resolve)
    monkeypatch.setattr("xwllz.discovery.scan_ports", fake_scan)
    monkeypatch.setattr("xwllz.discovery.probe_services", fake_probe)
    monkeypatch.setattr("xwllz.discovery.dns_engine.check_posture", fake_posture)

    stats = asyncio.run(run_discovery(conn, org, cfg))
    assert stats.hosts_resolved == 2
    assert stats.open_ports == 1
    snap = conn.execute("SELECT * FROM snapshots").fetchone()
    assert snap is not None