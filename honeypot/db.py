import json
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc TEXT NOT NULL,
            visitor_key TEXT NOT NULL,
            ip_anonymized TEXT NOT NULL,
            ip_raw TEXT,
            network_scope TEXT,
            url TEXT NOT NULL,
            path TEXT NOT NULL,
            method TEXT NOT NULL,
            user_agent TEXT,
            referer TEXT,
            status_code INTEGER,
            request_headers TEXT,
            response_headers TEXT,
            processing_ms REAL,
            cookies TEXT,
            get_params TEXT,
            post_params TEXT,
            category TEXT,
            robots_consulted INTEGER DEFAULT 0,
            sitemap_consulted INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts_utc);
        CREATE INDEX IF NOT EXISTS idx_requests_visitor ON requests(visitor_key);
        CREATE INDEX IF NOT EXISTS idx_requests_path ON requests(path);

        CREATE TABLE IF NOT EXISTS capability_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc TEXT NOT NULL,
            visitor_key TEXT NOT NULL,
            event_name TEXT NOT NULL,
            event_value TEXT,
            metadata TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_cap_vis ON capability_events(visitor_key);
        CREATE INDEX IF NOT EXISTS idx_cap_name ON capability_events(event_name);

        CREATE TABLE IF NOT EXISTS daily_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            day_utc TEXT NOT NULL UNIQUE,
            generated_at_utc TEXT NOT NULL,
            content_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS fingerprint_presets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            filters_json TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        );
        """
    )

    _ensure_column(db, "requests", "ip_raw", "TEXT")
    _ensure_column(db, "requests", "network_scope", "TEXT")

    db.commit()


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def json_dumps_safe(value):
    return json.dumps(value, ensure_ascii=True, default=str)


def insert_request_log(payload):
    db = get_db()
    db.execute(
        """
        INSERT INTO requests (
            ts_utc, visitor_key, ip_anonymized, ip_raw, network_scope, url, path, method, user_agent,
            referer, status_code, request_headers, response_headers,
            processing_ms, cookies, get_params, post_params, category,
            robots_consulted, sitemap_consulted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["ts_utc"],
            payload["visitor_key"],
            payload["ip_anonymized"],
            payload.get("ip_raw"),
            payload.get("network_scope"),
            payload["url"],
            payload["path"],
            payload["method"],
            payload.get("user_agent"),
            payload.get("referer"),
            payload.get("status_code"),
            json_dumps_safe(payload.get("request_headers", {})),
            json_dumps_safe(payload.get("response_headers", {})),
            payload.get("processing_ms"),
            json_dumps_safe(payload.get("cookies", {})),
            json_dumps_safe(payload.get("get_params", {})),
            json_dumps_safe(payload.get("post_params", {})),
            payload.get("category", "unknown"),
            int(payload.get("robots_consulted", False)),
            int(payload.get("sitemap_consulted", False)),
        ),
    )
    db.commit()


def insert_capability_event(visitor_key, event_name, event_value=None, metadata=None):
    db = get_db()
    db.execute(
        """
        INSERT INTO capability_events (ts_utc, visitor_key, event_name, event_value, metadata)
        VALUES (?, ?, ?, ?, ?)
        """,
        (utc_now_iso(), visitor_key, event_name, event_value, json_dumps_safe(metadata or {})),
    )
    db.commit()


def prune_request_logs(max_rows):
    db = get_db()
    row = db.execute("SELECT COUNT(*) AS c FROM requests").fetchone()
    total = row["c"] if row else 0
    if total <= max_rows:
        return 0

    to_delete = total - max_rows
    db.execute(
        """
        DELETE FROM requests
        WHERE id IN (
            SELECT id FROM requests ORDER BY id ASC LIMIT ?
        )
        """,
        (to_delete,),
    )
    db.commit()
    return to_delete


def list_fingerprint_presets():
    db = get_db()
    rows = db.execute(
        """
        SELECT id, name, filters_json, created_at_utc, updated_at_utc
        FROM fingerprint_presets
        ORDER BY name ASC
        """
    ).fetchall()
    presets = []
    for row in rows:
        try:
            filters = json.loads(row["filters_json"] or "{}")
        except json.JSONDecodeError:
            filters = {}
        presets.append(
            {
                "id": row["id"],
                "name": row["name"],
                "filters": filters,
                "created_at_utc": row["created_at_utc"],
                "updated_at_utc": row["updated_at_utc"],
            }
        )
    return presets


def upsert_fingerprint_preset(name, filters):
    db = get_db()
    now = utc_now_iso()
    db.execute(
        """
        INSERT INTO fingerprint_presets(name, filters_json, created_at_utc, updated_at_utc)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            filters_json=excluded.filters_json,
            updated_at_utc=excluded.updated_at_utc
        """,
        (name, json_dumps_safe(filters or {}), now, now),
    )
    db.commit()


def delete_fingerprint_preset(preset_id):
    db = get_db()
    cur = db.execute("DELETE FROM fingerprint_presets WHERE id = ?", (preset_id,))
    db.commit()
    return cur.rowcount


def _ensure_column(db, table_name, column_name, column_type):
    rows = db.execute(f"PRAGMA table_info({table_name})").fetchall()
    names = {row[1] for row in rows}
    if column_name in names:
        return
    db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
