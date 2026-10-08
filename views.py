"""Read-only projections over the existing observations table.

These functions only SELECT and reshape rows; they assign no verdicts and
merge nothing. All opinionated aggregation lives in aggregate.py.
"""

from __future__ import annotations

import json


def ips(conn) -> list[str]:
    return [row[0] for row in conn.execute("SELECT DISTINCT ip FROM observations ORDER BY ip")]


def sources(conn, ips: list[str] | None = None) -> list[str]:
    if ips:
        marks = ",".join("?" * len(ips))
        rows = conn.execute(
            f"SELECT DISTINCT source FROM observations WHERE ip IN ({marks}) ORDER BY source", ips
        )
    else:
        rows = conn.execute("SELECT DISTINCT source FROM observations ORDER BY source")
    return [row[0] for row in rows]


def keys(conn, ips: list[str] | None = None) -> list[tuple[str, str]]:
    if ips:
        marks = ",".join("?" * len(ips))
        rows = conn.execute(
            f"SELECT DISTINCT topic, key FROM observations WHERE ip IN ({marks}) ORDER BY topic, key",
            ips,
        )
    else:
        rows = conn.execute("SELECT DISTINCT topic, key FROM observations ORDER BY topic, key")
    return [(topic, key) for topic, key in rows]


def cells(conn, ips: list[str]) -> dict[tuple[str, str, str], dict[str, list]]:
    """(ip, topic, key) -> {source: [raw values]} for the given IPs."""
    marks = ",".join("?" * len(ips))
    out: dict[tuple[str, str, str], dict[str, list]] = {}
    for ip, topic, key, source, value in conn.execute(
        f"SELECT ip, topic, key, source, value FROM observations WHERE ip IN ({marks}) "
        "ORDER BY ip, topic, key, source",
        ips,
    ):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            pass
        out.setdefault((ip, topic, key), {}).setdefault(source, []).append(value)
    return out
