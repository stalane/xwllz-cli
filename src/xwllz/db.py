"""SQLite storage: schema, migrations, and a connection helper.

The DB lives at $XDG_DATA_HOME/xwllz/xwllz.db (default ~/.local/share/xwllz).
"""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    domains     TEXT NOT NULL,              -- comma-separated root domains
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS assets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id        INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    type          TEXT NOT NULL,            -- domain | subdomain | ip | url
    status        TEXT NOT NULL DEFAULT 'active',  -- active | removed
    source        TEXT,                     -- crtsh | dns | shodan | ...
    first_seen    TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(org_id, host, type)
);
CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id, status);

CREATE TABLE IF NOT EXISTS services (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id      INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port          INTEGER NOT NULL,
    proto         TEXT DEFAULT 'tcp',
    service       TEXT,                     -- http | https | ssh | smtp | ...
    banner        TEXT,
    tech          TEXT,                     -- comma-separated tech stack
    tls_expires   TEXT,                     -- ISO date of cert expiry
    http_title    TEXT,
    http_status   INTEGER,
    first_seen    TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(asset_id, port, proto)
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id        INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    asset_id      INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    service_id    INTEGER REFERENCES services(id) ON DELETE CASCADE,
    severity      TEXT NOT NULL,            -- info | low | medium | high
    kind          TEXT NOT NULL,            -- tls_expiry | spf | dmarc | ...
    title         TEXT NOT NULL,
    detail        TEXT,
    source        TEXT,                     -- detector | nuclei | ...
    first_seen    TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_findings ON findings(
    org_id, kind, COALESCE(asset_id, 0), COALESCE(service_id, 0), title
);

CREATE TABLE IF NOT EXISTS snapshots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id        INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    scanned_at    TEXT NOT NULL DEFAULT (datetime('now')),
    assets        INTEGER NOT NULL DEFAULT 0,
    services      INTEGER NOT NULL DEFAULT 0,
    findings      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS intel (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator   TEXT NOT NULL,
    type        TEXT NOT NULL,              -- domain | ip | url | hash
    verdict     TEXT,                       -- clean | malicious | suspicious | unknown
    source      TEXT NOT NULL,
    data        TEXT,                       -- JSON payload
    checked_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(indicator, type, source)
);
"""


def default_db_path() -> Path:
    """Return the default database location (XDG data dir + xwllz)."""
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    return Path(base) / "xwllz" / "xwllz.db"


def connect(path: str | os.PathLike[str] | None = None) -> sqlite3.Connection:
    """Open (creating if needed) the xwllz database and ensure the schema."""
    db_path = Path(path) if path else default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def upsert_asset(conn: sqlite3.Connection, org_id: int, host: str, type_: str, source: str) -> int:
    """Insert or touch an asset; returns its id."""
    conn.execute(
        """
        INSERT INTO assets (org_id, host, type, source)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(org_id, host, type) DO UPDATE SET
            last_seen = datetime('now'),
            status = 'active'
        """,
        (org_id, host, type_, source),
    )
    conn.commit()
    row = conn.execute(
        "SELECT id FROM assets WHERE org_id = ? AND host = ? AND type = ?",
        (org_id, host, type_),
    ).fetchone()
    if row is None:
        raise RuntimeError("asset upsert failed")
    return int(row["id"])


def mark_removed(conn: sqlite3.Connection, org_id: int, host: str, type_: str) -> None:
    """Mark an asset as removed (no longer seen)."""
    conn.execute(
        "UPDATE assets SET status = 'removed' WHERE org_id = ? AND host = ? AND type = ?",
        (org_id, host, type_),
    )
    conn.commit()


def upsert_service(
    conn: sqlite3.Connection,
    asset_id: int,
    port: int,
    proto: str,
    service: str | None = None,
    banner: str | None = None,
    tech: str | None = None,
    tls_expires: str | None = None,
    http_title: str | None = None,
    http_status: int | None = None,
) -> int:
    """Insert or touch a service; returns its id."""
    conn.execute(
        """
        INSERT INTO services
            (asset_id, port, proto, service, banner, tech, tls_expires, http_title, http_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(asset_id, port, proto) DO UPDATE SET
            service     = COALESCE(excluded.service, services.service),
            banner      = COALESCE(excluded.banner, services.banner),
            tech        = COALESCE(excluded.tech, services.tech),
            tls_expires = COALESCE(excluded.tls_expires, services.tls_expires),
            http_title  = COALESCE(excluded.http_title, services.http_title),
            http_status = COALESCE(excluded.http_status, services.http_status),
            last_seen   = datetime('now')
        """,
        (asset_id, port, proto, service, banner, tech, tls_expires, http_title, http_status),
    )
    conn.commit()
    row = conn.execute(
        "SELECT id FROM services WHERE asset_id = ? AND port = ? AND proto = ?",
        (asset_id, port, proto),
    ).fetchone()
    if row is None:
        raise RuntimeError("service upsert failed")
    return int(row["id"])


def upsert_finding(
    conn: sqlite3.Connection,
    org_id: int,
    severity: str,
    kind: str,
    title: str,
    detail: str | None = None,
    source: str = "detector",
    asset_id: int | None = None,
    service_id: int | None = None,
) -> int:
    """Insert or touch a finding; returns its id.

    Dedupe matches on org + kind + asset + service + title (NULL asset/service
    coerce to 0 so they compare equal).
    """
    existing = conn.execute(
        """
        SELECT id FROM findings
        WHERE org_id = ? AND kind = ?
          AND COALESCE(asset_id, 0) = COALESCE(?, 0)
          AND COALESCE(service_id, 0) = COALESCE(?, 0)
          AND title = ?
        """,
        (org_id, kind, asset_id, service_id, title),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE findings SET detail = ?, last_seen = datetime('now') WHERE id = ?",
            (detail, int(existing["id"])),
        )
        conn.commit()
        return int(existing["id"])
    cur = conn.execute(
        """
        INSERT INTO findings (org_id, asset_id, service_id, severity, kind, title, detail, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (org_id, asset_id, service_id, severity, kind, title, detail, source),
    )
    conn.commit()
    return int(cur.lastrowid)


def org_id_by_name(conn: sqlite3.Connection, name: str) -> int | None:
    row = conn.execute("SELECT id FROM orgs WHERE name = ?", (name,)).fetchone()
    return int(row["id"]) if row else None


if __name__ == "__main__":  # pragma: no cover
    conn = connect(sys.argv[1] if len(sys.argv) > 1 else None)
    print(f"schema ready at {default_db_path()}")