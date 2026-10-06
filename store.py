"""SQLite raw store."""

from __future__ import annotations

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
            source TEXT NOT NULL,
            url TEXT NOT NULL,
            status INTEGER,
            body TEXT,
            error TEXT,
            fetched_at TEXT NOT NULL
        )
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
) -> None:
    conn.execute(
        "INSERT INTO fetches (source, url, status, body, error, fetched_at) VALUES (?, ?, ?, ?, ?, ?)",
        (source, url, status, body, error, now()),
    )
    conn.commit()
