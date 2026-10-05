#!/usr/bin/env python3
"""aranya - phase 0 prototype.

Raw-minimal end-to-end slice: fetch one source for one IP, keep the raw
response in SQLite, and show the normalized field. Nothing else yet.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

SOURCE = "ripestat.network-info"
URL = "https://stat.ripe.net/data/network-info/data.json?resource={ip}"
TIMEOUT = 15
USER_AGENT = "aranya/0.0"
DEFAULT_DB = "aranya.db"


def fetch(url: str, timeout: int = TIMEOUT) -> tuple[int | None, str | None, str | None]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, body, f"HTTP {exc.code}"
    except Exception as exc:
        return None, None, str(exc)


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
        (source, url, status, body, error, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def parse_network_info(body: str) -> dict:
    payload = json.loads(body)
    if not isinstance(payload, dict):
        return {"prefix": None, "asns": []}
    data = payload.get("data") or {}
    if not isinstance(data, dict):
        return {"prefix": None, "asns": []}
    asns = data.get("asns")
    return {"prefix": data.get("prefix"), "asns": asns if isinstance(asns, list) else []}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="aranya phase 0 prototype")
    parser.add_argument("ip", help="IP address to look up")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite file (default: %(default)s)")
    args = parser.parse_args(argv)

    url = URL.format(ip=args.ip)
    conn = open_store(args.db)
    status, body, error = fetch(url)
    save_fetch(conn, SOURCE, url, status, body, error)
    conn.close()

    if error:
        print(f"{SOURCE}: error: {error}", file=sys.stderr)
        return 1

    try:
        result = parse_network_info(body)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"{SOURCE}: parse error: {exc}", file=sys.stderr)
        return 1

    print(f"{args.ip} -> prefix={result['prefix']} asns={result['asns']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
