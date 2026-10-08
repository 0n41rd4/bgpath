"""Build a deterministic JSON export of the observation views.

Read-only over the store. Consumed by the text CLI and by the HTML report
(template.html). No generated_at: the output is a pure function of the data.
"""

from __future__ import annotations

import json
import os
import sqlite3

import aggregate
import sources
import views

SCHEMA_VERSION = 1
TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template.html")
WORLD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "world.txt")
DATA_TOKEN = "/*__ARANYA_DATA__*/null"
LAND_TOKEN = "/*__ARANYA_LAND__*/null"


def _all_sources(conn) -> list[dict]:
    registry = {adapter["id"]: adapter.get("upstream") for adapter in sources.SOURCES}
    observed = {row[0] for row in conn.execute("SELECT DISTINCT source FROM observations")}
    fetched = {row[0] for row in conn.execute("SELECT DISTINCT source FROM fetches")}
    ids = [adapter["id"] for adapter in sources.SOURCES] + sorted((observed | fetched) - set(registry))
    mapping = aggregate.upstream_map(conn)
    return [{"id": source, "upstream": mapping.get(source, source)} for source in ids]


def _fetch_states(conn, ips: list[str]) -> dict[tuple[str, str], dict]:
    if not ips:
        return {}
    marks = ",".join("?" * len(ips))
    latest: dict[tuple[str, str], dict] = {}
    for ip, source, status, error, fetch_id in conn.execute(
        f"SELECT ip, source, status, error, id FROM fetches WHERE ip IN ({marks}) ORDER BY id", ips
    ):
        latest[(ip, source)] = {"status": status, "error": error, "last_fetch_id": fetch_id}
    for record in latest.values():
        error = record["error"] or ""
        if error.startswith("skipped"):
            record["state"] = "skipped"
        elif error or record["status"] is None or not 200 <= record["status"] < 400:
            record["state"] = "error"
        else:
            record["state"] = "ok"
    return latest


def _source_summary(states: list[dict]) -> list[dict]:
    counts: dict[str, dict[str, int]] = {}
    for cell in states:
        row = counts.setdefault(cell["source"], {})
        row[cell["state"]] = row.get(cell["state"], 0) + 1
    return [
        {"source": source, "total": sum(row.values()), **row}
        for source, row in sorted(counts.items())
    ]


def _matches(topic: str, key: str, topics: set[str] | None) -> bool:
    if not topics:
        return True
    return topic in topics or f"{topic}.{key}" in topics or key in topics


def _in_clause(column: str, ips: list[str]) -> tuple[str, list[str]]:
    if not ips:
        return " WHERE 0", []
    return f" WHERE {column} IN ({','.join('?' * len(ips))})", list(ips)


def build(
    conn: sqlite3.Connection,
    ips: list[str] | None = None,
    topics: set[str] | None = None,
    with_observations: bool = False,
) -> dict:
    all_ips = views.ips(conn)
    ips = [ip for ip in all_ips if ips is None or ip in ips]
    upstream = aggregate.upstream_map(conn)
    cells = views.cells(conn, ips)
    fetch_states = _fetch_states(conn, ips)
    source_ids = [row["id"] for row in _all_sources(conn)]
    ran_ok = {(ip, source) for (ip, _t, _k), values in cells.items() for source in values}
    ran_ok |= {key for key, record in fetch_states.items() if record["state"] == "ok"}

    claims = []
    states = []
    for (ip, topic, key), source_values in sorted(cells.items()):
        if not _matches(topic, key, topics):
            continue
        summary = {"ip": ip, **aggregate.summarize(topic, key, source_values, upstream)}
        claims.append(summary)
        multi = set(summary["multi"])
        present = set(source_values)
        for source in source_ids:
            fetch = fetch_states.get((ip, source))
            if fetch and fetch["state"] != "ok":
                state = fetch["state"]
            elif source in present and source in multi:
                state = "multi"
            elif source in present and summary["verdict"] == "single":
                state = "single"
            elif source in present and summary["source_labels"][source][0] == summary["consensus"]:
                state = "agree"
            elif source in present:
                state = "dissent"
            elif (ip, source) in ran_ok:
                state = "no_data"
            else:
                state = "absent"
            states.append({"ip": ip, "topic": topic, "key": key, "source": source, "state": state})

    where, params = _in_clause("ip", ips)
    locations = [
        {"ip": ip, "source": source, "city": city, "country": country,
         "latitude": latitude, "longitude": longitude}
        for ip, source, city, country, latitude, longitude in conn.execute(
            "SELECT ip, source, city, country, latitude, longitude FROM v_locations" + where, params
        )
    ]
    latency = [
        {"ip": ip, "source": source, "city": city, "country": country,
         "avg_rtt": avg_rtt, "min_rtt": min_rtt, "loss": loss}
        for ip, source, city, country, avg_rtt, min_rtt, loss in conn.execute(
            "SELECT ip, source, city, country, avg_rtt, min_rtt, loss FROM v_latency" + where, params
        )
    ]
    fetch_index = [
        {"id": fid, "ip": ip, "source": source, "url": url, "status": status,
         "error": error, "fetched_at": fetched_at}
        for fid, ip, source, url, status, error, fetched_at in conn.execute(
            "SELECT id, ip, source, url, status, error, fetched_at FROM fetches" + where, params
        )
    ]

    observed_at = conn.execute("SELECT MAX(observed_at) FROM observations").fetchone()[0]
    obj = {
        "schema_version": SCHEMA_VERSION,
        "latest_observation": observed_at,
        "ips": ips,
        "sources": _all_sources(conn),
        "claims": claims,
        "states": states,
        "locations": sorted(locations, key=lambda r: (r["ip"], r["source"], str(r["city"]))),
        "latency": sorted(latency, key=lambda r: (r["ip"], r["source"], str(r["city"]))),
        "source_summary": _source_summary(states),
        "fetches": sorted(fetch_index, key=lambda r: r["id"]),
    }
    if with_observations:
        obj["observations"] = [
            {"ip": ip, "source": source, "upstream": upstream_name, "evidence_class": evidence_class,
             "topic": topic, "key": key, "value": json.loads(value), "observed_at": observed_at_,
             "fetch_id": fetch_id}
            for ip, source, upstream_name, evidence_class, topic, key, value, observed_at_, fetch_id in conn.execute(
                "SELECT ip, source, upstream, evidence_class, topic, key, value, observed_at, fetch_id "
                "FROM observations ORDER BY ip, topic, key, source, id"
            )
            if ip in ips and _matches(topic, key, topics)
        ]
    return obj


def to_json(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _embed(obj: dict) -> str:
    text = to_json(obj)
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_html(obj: dict, template_path: str = TEMPLATE) -> str:
    with open(template_path, encoding="utf-8") as handle:
        template = handle.read()
    with open(WORLD, encoding="utf-8") as handle:
        land = json.dumps(handle.read())
    return template.replace(DATA_TOKEN, _embed(obj)).replace(LAND_TOKEN, land)
