"""Storage for measurement runs, raw hops, and the topological graph.

Separate from aranya's observations store: this one keeps the raw interface
layer (hops) and the derived graph (nodes/edges), keyed by layer so the router,
AS, IXP and facility topologies never collapse into each other.
"""

from __future__ import annotations

import json
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    target     TEXT NOT NULL,
    port       INTEGER,
    proto      TEXT,
    src_ip     TEXT,
    tool       TEXT,
    started_at TEXT,
    meta       TEXT
);
CREATE TABLE IF NOT EXISTS hops (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     TEXT NOT NULL,
    flow_id    INTEGER,
    ttl        INTEGER,
    src_ip     TEXT,
    rtt_ms     REAL,
    icmp_type  INTEGER,
    icmp_code  INTEGER,
    reply_ttl  INTEGER,
    ip_id      INTEGER,
    nat_id     INTEGER,
    mpls       TEXT,
    is_last    INTEGER DEFAULT 0,
    name       TEXT,
    protocol   TEXT,
    tool       TEXT
);
CREATE INDEX IF NOT EXISTS idx_hops_run ON hops(run_id);
CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    layer   TEXT NOT NULL,
    key     TEXT NOT NULL,
    attrs   TEXT
);
CREATE TABLE IF NOT EXISTS edges (
    run_id     TEXT NOT NULL,
    layer      TEXT NOT NULL,
    src        TEXT NOT NULL,
    dst        TEXT NOT NULL,
    ttl        INTEGER,
    count      INTEGER DEFAULT 1,
    min_rtt_ms REAL,
    attrs      TEXT,
    PRIMARY KEY (run_id, layer, src, dst)
);
CREATE INDEX IF NOT EXISTS idx_edges_run ON edges(run_id, layer);
"""


def open_store(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(hops)")}
    for column in ("protocol", "tool"):
        if column not in columns:
            conn.execute(f"ALTER TABLE hops ADD COLUMN {column} TEXT")
    return conn


def save_run(conn: sqlite3.Connection, run: dict) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO runs (run_id, target, port, proto, src_ip, tool, started_at, meta) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run["run_id"],
            run["target"],
            run.get("port"),
            run.get("proto"),
            run.get("src_ip"),
            run.get("tool"),
            run.get("started_at"),
            json.dumps(run.get("meta") or {}, sort_keys=True),
        ),
    )
    conn.commit()


def save_hops(conn: sqlite3.Connection, run_id: str, hops: list[dict]) -> None:
    conn.executemany(
        "INSERT INTO hops (run_id, flow_id, ttl, src_ip, rtt_ms, icmp_type, icmp_code, "
        "reply_ttl, ip_id, nat_id, mpls, is_last, name, protocol, tool) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                run_id,
                hop.get("flow_id"),
                hop.get("ttl"),
                hop.get("src_ip"),
                hop.get("rtt_ms"),
                hop.get("icmp_type"),
                hop.get("icmp_code"),
                hop.get("reply_ttl"),
                hop.get("ip_id"),
                hop.get("nat_id"),
                json.dumps(hop.get("mpls") or []),
                1 if hop.get("is_last") else 0,
                hop.get("name"),
                hop.get("protocol"),
                hop.get("tool"),
            )
            for hop in hops
        ],
    )
    conn.commit()


def load_hops(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT flow_id, ttl, src_ip, rtt_ms, icmp_type, icmp_code, reply_ttl, ip_id, nat_id, mpls, is_last, protocol, tool "
        "FROM hops WHERE run_id = ?",
        (run_id,),
    ).fetchall()
    return [
        {
            "flow_id": flow, "ttl": ttl, "src_ip": ip, "rtt_ms": rtt,
            "icmp_type": icmp_type, "icmp_code": icmp_code, "reply_ttl": reply,
            "ip_id": ip_id, "nat_id": nat_id, "mpls": json.loads(mpls or "[]"),
            "is_last": bool(is_last), "protocol": protocol, "tool": tool,
        }
        for flow, ttl, ip, rtt, icmp_type, icmp_code, reply, ip_id, nat_id, mpls, is_last, protocol, tool in rows
    ]


def add_node(conn: sqlite3.Connection, layer: str, key: str, attrs: dict | None = None) -> str:
    node_id = f"{layer}:{key}"
    conn.execute(
        "INSERT INTO nodes (node_id, layer, key, attrs) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(node_id) DO UPDATE SET attrs = excluded.attrs",
        (node_id, layer, str(key), json.dumps(attrs or {}, sort_keys=True)),
    )
    return node_id


def add_edge(
    conn: sqlite3.Connection,
    run_id: str,
    layer: str,
    src: str,
    dst: str,
    ttl: int | None = None,
    rtt_ms: float | None = None,
    attrs: dict | None = None,
) -> None:
    conn.execute(
        "INSERT INTO edges (run_id, layer, src, dst, ttl, count, min_rtt_ms, attrs) "
        "VALUES (?, ?, ?, ?, ?, 1, ?, ?) "
        "ON CONFLICT(run_id, layer, src, dst) DO UPDATE SET "
        "count = count + 1, "
        "min_rtt_ms = MIN(COALESCE(min_rtt_ms, excluded.min_rtt_ms), excluded.min_rtt_ms), "
        "attrs = excluded.attrs",
        (run_id, layer, src, dst, ttl, rtt_ms, json.dumps(attrs or {}, sort_keys=True)),
    )


def commit(conn: sqlite3.Connection) -> None:
    conn.commit()


def clear_layer(conn: sqlite3.Connection, run_id: str, layer: str) -> None:
    conn.execute("DELETE FROM edges WHERE run_id = ? AND layer = ?", (run_id, layer))
    conn.commit()


def graph_counts(conn: sqlite3.Connection, run_id: str) -> dict:
    nodes = conn.execute("SELECT layer, COUNT(*) FROM nodes GROUP BY layer").fetchall()
    edges = conn.execute(
        "SELECT layer, COUNT(*), SUM(count) FROM edges WHERE run_id = ? GROUP BY layer",
        (run_id,),
    ).fetchall()
    return {
        "nodes": {layer: count for layer, count in nodes},
        "edges": {layer: {"distinct": distinct, "observations": observed} for layer, distinct, observed in edges},
    }
