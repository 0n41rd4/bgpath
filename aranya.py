#!/usr/bin/env python3
"""aranya - evidence layer over public internet-infrastructure data.

Phase 1 prototype: fetch every configured source for an IP, keep the raw
responses, and show the parsed result per source.
"""

from __future__ import annotations

import argparse
import json
import time

import sources
import store

DEFAULT_DB = "aranya.db"


def run_adapter(conn, adapter: dict, ip: str, context: dict) -> tuple[str, object]:
    url = adapter["url"](context)
    if adapter.get("delay"):
        time.sleep(adapter["delay"])
    if "fetch" in adapter:
        status, body, error = adapter["fetch"](ip, context)
    else:
        status, body, error = sources.http_get(url)
    store.save_fetch(conn, adapter["id"], url, status, body, error)

    if error:
        return f"error ({error})", None

    try:
        parsed = adapter["parse"](body)
    except ValueError as exc:
        return f"parse error ({exc})", None

    for key, value in adapter["provides"](parsed).items():
        if value is not None:
            context[key] = value

    return "ok", parsed


def run_all(conn, ip: str) -> dict:
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
            status, parsed = run_adapter(conn, adapter, ip, context)
            statuses[adapter["id"]] = status
            parsed_results[adapter["id"]] = parsed

    for adapter in remaining:
        statuses[adapter["id"]] = f"skipped (missing {', '.join(adapter['needs'])})"

    return statuses, parsed_results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="aranya phase 1 prototype")
    parser.add_argument("ip", help="IP address to look up")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite file (default: %(default)s)")
    args = parser.parse_args(argv)

    conn = store.open_store(args.db)
    statuses, parsed = run_all(conn, args.ip)
    conn.close()

    print(f"aranya {args.ip}\n")
    print("sources:")
    for adapter in sources.SOURCES:
        print(f"  {statuses[adapter['id']]:<12} {adapter['id']}")

    print("\nparsed:")
    for adapter in sources.SOURCES:
        if parsed.get(adapter["id"]) is not None:
            print(f"  {adapter['id']}: {json.dumps(parsed[adapter['id']], ensure_ascii=False)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
