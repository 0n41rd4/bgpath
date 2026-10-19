"""SQLite raw store and observations."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def open_store(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fetches (
            id INTEGER PRIMARY KEY,
            ip TEXT,
            source TEXT NOT NULL,
            url TEXT NOT NULL,
            status INTEGER,
            body TEXT,
            error TEXT,
            fetched_at TEXT NOT NULL
        )
        """
    )
    fetch_cols = {row[1] for row in conn.execute("PRAGMA table_info(fetches)")}
    if "ip" not in fetch_cols:
        conn.execute("ALTER TABLE fetches ADD COLUMN ip TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY,
            ip TEXT NOT NULL,
            source TEXT NOT NULL,
            upstream TEXT,
            evidence_class TEXT,
            topic TEXT NOT NULL,
            key TEXT,
            value TEXT,
            fetch_id INTEGER,
            observed_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE VIEW IF NOT EXISTS v_observations AS
        SELECT ip, source, upstream, evidence_class, topic, key, value, observed_at
        FROM observations
        ORDER BY ip, source, topic, key
        """
    )
    conn.execute(
        """
        CREATE VIEW IF NOT EXISTS v_locations AS
        SELECT ip, source, upstream, evidence_class,
               json_extract(value, '$.city') AS city,
               json_extract(value, '$.country') AS country,
               json_extract(value, '$.latitude') AS latitude,
               json_extract(value, '$.longitude') AS longitude
        FROM observations
        WHERE topic = 'location'
        """
    )
    conn.execute(
        """
        CREATE VIEW IF NOT EXISTS v_latency AS
        SELECT ip, source, upstream, evidence_class,
               json_extract(value, '$.city') AS city,
               json_extract(value, '$.country') AS country,
               json_extract(value, '$.latitude') AS latitude,
               json_extract(value, '$.longitude') AS longitude,
               json_extract(value, '$.avg_rtt') AS avg_rtt,
               json_extract(value, '$.min_rtt') AS min_rtt,
               json_extract(value, '$.loss') AS loss
        FROM observations
        WHERE topic = 'latency'
        """
    )
    conn.commit()
    return conn


def save_fetch(
    conn: sqlite3.Connection,
    source: str,
    url: str,
    status: int | None,
    body: str | None,
    error: str | None,
    ip: str | None = None,
) -> int:
    cursor = conn.execute(
        "INSERT INTO fetches (ip, source, url, status, body, error, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ip, source, url, status, body, error, now()),
    )
    conn.commit()
    return cursor.lastrowid


def save_observation(
    conn: sqlite3.Connection,
    ip: str,
    source: str,
    upstream: str | None,
    evidence_class: str | None,
    topic: str,
    key: str | None,
    value: object,
    fetch_id: int | None = None,
) -> None:
    conn.execute(
        "INSERT INTO observations (ip, source, upstream, evidence_class, topic, key, value, fetch_id, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ip, source, upstream, evidence_class, topic, key, json.dumps(value), fetch_id, now()),
    )
    conn.commit()
