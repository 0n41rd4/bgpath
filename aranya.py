#!/usr/bin/env python3
"""aranya - evidence layer over public internet-infrastructure data.

Phase 1 prototype: fetch every configured source for an IP, keep the raw
responses, and show the parsed result per source.
"""

from __future__ import annotations

import argparse
import json
import time

import compare
import normalize
import sources
import store

DEFAULT_DB = "aranya.db"


def run_adapter(
    conn,
    adapter: dict,
    ip: str,
    context: dict,
    fetch=None,
) -> tuple[str, object]:
    if "precheck" in adapter:
        reason = adapter["precheck"]()
        if reason:
            return f"skipped ({reason})", None

    url = adapter["url"](context)
    if adapter.get("delay") and fetch is None:
        time.sleep(adapter["delay"])
    if fetch is not None:
        status, body, error = fetch(url)
    elif "fetch" in adapter:
        status, body, error = adapter["fetch"](ip, context)
    else:
        status, body, error = sources.http_get(url)
    fetch_id = store.save_fetch(conn, adapter["id"], sources.redact_url(url), status, body, error)

    if error:
        return f"error ({error})", None

    try:
        parsed, observations = normalize.normalize(adapter, ip, body)
    except ValueError as exc:
        return f"parse error ({exc})", None

    for key, value in adapter["provides"](parsed).items():
        if value is not None:
            context[key] = value

    for obs in observations:
        if obs["value"] is None:
            continue
        store.save_observation(
            conn,
            ip,
            adapter["id"],
            adapter["upstream"],
            adapter["evidence_class"],
            obs["topic"],
            obs["key"],
            obs["value"],
            fetch_id,
        )

    return "ok", parsed


def run_all(conn, ip: str, fetch=None) -> dict:
    context: dict = {"ip": ip}
    remaining = list(sources.SOURCES)
    statuses: dict[str, str] = {}
    parsed_results: dict[str, object] = {}

    progressed = True
    while remaining and progressed:
        progressed = False
        for adapter in list(remaining):
            if not all(key in context for key in adapter["needs"]):
                continue
            remaining.remove(adapter)
            progressed = True
            status, parsed = run_adapter(conn, adapter, ip, context, fetch)
            statuses[adapter["id"]] = status
            parsed_results[adapter["id"]] = parsed

    for adapter in remaining:
        statuses[adapter["id"]] = f"skipped (missing {', '.join(adapter['needs'])})"

    return statuses, parsed_results


def _fmt(value: object, limit: int = 100) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def print_summary(conn, ip: str) -> None:
    print("\nobservations:")
    last_topic = None
    for topic, source, key, value in conn.execute(
        "SELECT topic, source, key, value FROM v_observations WHERE ip = ?", (ip,)
    ):
        if topic != last_topic:
            print(f"  [{topic}]")
            last_topic = topic
        print(f"    {source:<22} {key:<12} {_fmt(json.loads(value))}")

    print("\nlocations (v_locations):")
    for source, city, country, latitude, longitude in conn.execute(
        "SELECT source, city, country, latitude, longitude FROM v_locations WHERE ip = ?",
        (ip,),
    ):
        print(f"    {source:<22} {city} | {country} | {latitude} | {longitude}")


def print_comparison(conn, ip: str) -> None:
    marks = {"agree": "=", "disagree": "!", "spread": "~"}
    print("\ncomparison:")
    for row in compare.summarize(conn, ip):
        mark = marks[row["verdict"]]
        print(f"  [{mark}] {row['topic']}.{row['key']}  ({row['verdict']})")
        for value, sources in row["values"].items():
            print(f"       {_fmt(json.loads(value))}  <-  {', '.join(sources)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="aranya phase 1 prototype")
    parser.add_argument("ip", help="IP address to look up")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite file (default: %(default)s)")
    args = parser.parse_args(argv)

    conn = store.open_store(args.db)
    statuses, _ = run_all(conn, args.ip)

    print(f"aranya {args.ip}\n")
    print("sources:")
    for adapter in sources.SOURCES:
        print(f"  {statuses[adapter['id']]:<12} {adapter['id']}")

    print_summary(conn, args.ip)
    print_comparison(conn, args.ip)
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
