#!/usr/bin/env python3
"""aranya - evidence layer over public internet-infrastructure data.

Phase 1 prototype: fetch every configured source for an IP, keep the raw
responses, and show the parsed result per source.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import compare
import export
import observe
import render
import sources
import store
import views

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
            store.save_fetch(conn, adapter["id"], adapter["id"], None, None, f"skipped ({reason})", ip)
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
    fetch_id = store.save_fetch(conn, adapter["id"], sources.redact_url(url), status, body, error, ip)

    if error:
        return f"error ({error})", None

    try:
        parsed, observations = observe.observe(adapter, ip, body)
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
        status = f"skipped (missing {', '.join(adapter['needs'])})"
        statuses[adapter["id"]] = status
        store.save_fetch(conn, adapter["id"], adapter["id"], None, None, status, ip)

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


def show_fetch(conn, fetch_id: int) -> int:
    row = conn.execute(
        "SELECT id, ip, source, url, status, error, fetched_at, body FROM fetches WHERE id = ?",
        (fetch_id,),
    ).fetchone()
    if not row:
        print(f"no fetch with id {fetch_id}")
        return 1
    fid, ip, source, url, status, error, fetched_at, body = row
    print(f"fetch {fid}  {source}  {ip}  status={status}  {fetched_at}")
    print(f"url: {url}")
    if error:
        print(f"error: {error}")
    print("---")
    print(body or "")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="aranya phase 1 prototype")
    parser.add_argument("ip", nargs="?", help="IP address to look up")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite file (default: %(default)s)")
    parser.add_argument("--view", action="store_true", help="render the claim view for IP (no fetch)")
    parser.add_argument("--normalize", action="store_true", help="canonicalize values before comparing (with --view)")
    parser.add_argument("--entities", action="store_true", help="resolve the IP's ownership entity")
    parser.add_argument("--report", action="store_true", help="cross-IP overview + agreement profile")
    parser.add_argument("--stats", action="store_true", help="cross-IP analysis over the store")
    parser.add_argument("--export", metavar="FILE", help="write the JSON contract (no fetch)")
    parser.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    parser.add_argument("--ips", help="comma-separated IP filter for --export/--html")
    parser.add_argument("--topics", help="comma-separated topic or topic.key filter")
    parser.add_argument("--with-observations", action="store_true", help="embed raw observations in export")
    parser.add_argument("--show-fetch", type=int, metavar="ID", help="print a stored fetch body")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = parser.parse_args(argv)

    color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
    conn = store.open_store(args.db)

    if args.show_fetch is not None:
        code = show_fetch(conn, args.show_fetch)
        conn.close()
        return code

    if args.export or args.html:
        ips = args.ips.split(",") if args.ips else ([args.ip] if args.ip else None)
        topics = set(args.topics.split(",")) if args.topics else None
        obj = export.build(conn, ips=ips, topics=topics, with_observations=args.with_observations)
        if args.export:
            with open(args.export, "w", encoding="utf-8") as handle:
                handle.write(export.to_json(obj))
            print(f"wrote {args.export}")
        if args.html:
            with open(args.html, "w", encoding="utf-8") as handle:
                handle.write(export.render_html(obj))
            print(f"wrote {args.html}")
        conn.close()
        return 0

    if args.report:
        ips = views.ips(conn)
        print("\n".join(render.overview_view(conn, ips, color)))
        print("\n".join(render.profile_view(conn, ips, color)))
        conn.close()
        return 0

    if args.stats:
        ips = [args.ip] if args.ip else None
        print("\n".join(render.stats_view(conn, ips, color)))
        conn.close()
        return 0

    if args.entities:
        if not args.ip:
            parser.error("--entities needs an IP")
        print("\n".join(render.entities_view(conn, args.ip, color)))
        conn.close()
        return 0

    if args.view:
        if not args.ip:
            parser.error("--view needs an IP")
        print("\n".join(render.claim_view(conn, args.ip, color, normalized=args.normalize)))
        conn.close()
        return 0

    if not args.ip:
        parser.error("an IP is required (or use --report/--export/--html)")

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
