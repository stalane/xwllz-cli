import json

import pytest

from xwllz import db, report
from xwllz.discovery import Org, snapshot


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(tmp_path / "test.db")
    c.execute("INSERT INTO orgs (name, domains) VALUES ('acme', 'example.com')")
    c.commit()
    org_id = db.org_id_by_name(c, "acme")
    aid = db.upsert_asset(c, org_id, "www.example.com", "subdomain", "dns")
    db.upsert_service(c, aid, 443, "tcp", service="https", http_title="Home", tech="nginx")
    db.upsert_finding(c, org_id, "medium", "spf", "Missing SPF record", "no spf", asset_id=aid)
    snapshot(c, Org(id=org_id, name="acme", domains=["example.com"]))
    yield c
    c.close()


def test_render_md(conn):
    body = report.render(conn, "acme", "md")
    assert "# xwllz report — acme" in body
    assert "Missing SPF record" in body
    assert "www.example.com:443" in body
    assert "medium" in body


def test_render_json(conn):
    body = report.render(conn, "acme", "json")
    data = json.loads(body)
    assert data["org"]["name"] == "acme"
    assert len(data["assets"]) == 1
    assert len(data["findings"]) == 1
    assert data["services"][0]["port"] == 443


def test_render_html(conn):
    body = report.render(conn, "acme", "html")
    assert body.startswith("<!DOCTYPE html>")
    assert "Missing SPF record" in body


def test_render_unknown_org(conn):
    with pytest.raises(KeyError):
        report.render(conn, "nope", "md")