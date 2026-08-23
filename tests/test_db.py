import pytest

from xwllz import db


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(tmp_path / "test.db")
    yield c
    c.close()


def test_schema_created(conn):
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    names = {r["name"] for r in tables}
    assert {"orgs", "assets", "services", "findings", "snapshots", "intel"} <= names


def test_org_and_asset_roundtrip(conn):
    conn.execute("INSERT INTO orgs (name, domains) VALUES ('acme', 'example.com')")
    conn.commit()
    org_id = db.org_id_by_name(conn, "acme")
    assert org_id is not None

    aid = db.upsert_asset(conn, org_id, "www.example.com", "subdomain", "dns")
    aid2 = db.upsert_asset(conn, org_id, "www.example.com", "subdomain", "dns")
    assert aid == aid2

    rows = conn.execute(
        "SELECT COUNT(*) n FROM assets WHERE org_id=? AND status='active'", (org_id,)
    ).fetchone()
    assert rows["n"] == 1


def test_asset_mark_removed(conn):
    conn.execute("INSERT INTO orgs (name, domains) VALUES ('acme', 'example.com')")
    conn.commit()
    org_id = db.org_id_by_name(conn, "acme")
    db.upsert_asset(conn, org_id, "old.example.com", "subdomain", "dns")
    db.mark_removed(conn, org_id, "old.example.com", "subdomain")
    row = conn.execute(
        "SELECT status FROM assets WHERE org_id=? AND host='old.example.com'", (org_id,)
    ).fetchone()
    assert row["status"] == "removed"


def test_service_dedupe(conn):
    conn.execute("INSERT INTO orgs (name, domains) VALUES ('acme', 'example.com')")
    conn.commit()
    org_id = db.org_id_by_name(conn, "acme")
    aid = db.upsert_asset(conn, org_id, "www.example.com", "subdomain", "dns")

    sid = db.upsert_service(conn, aid, 443, "tcp", service="https", http_title="Home")
    sid2 = db.upsert_service(conn, aid, 443, "tcp", service="https", http_title="Home")
    assert sid == sid2
    row = conn.execute("SELECT COUNT(*) n FROM services WHERE asset_id=?", (aid,)).fetchone()
    assert row["n"] == 1


def test_finding_dedupe(conn):
    conn.execute("INSERT INTO orgs (name, domains) VALUES ('acme', 'example.com')")
    conn.commit()
    org_id = db.org_id_by_name(conn, "acme")
    aid = db.upsert_asset(conn, org_id, "www.example.com", "subdomain", "dns")

    db.upsert_finding(conn, org_id, "medium", "spf", "Missing SPF record", "detail", asset_id=aid)
    db.upsert_finding(conn, org_id, "medium", "spf", "Missing SPF record", "detail", asset_id=aid)
    rows = conn.execute("SELECT COUNT(*) n FROM findings WHERE org_id=?", (org_id,)).fetchone()
    assert rows["n"] == 1


def test_default_db_path_uses_xdg(monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "/tmp/xdg-test")
    assert str(db.default_db_path()) == "/tmp/xdg-test/xwllz/xwllz.db"