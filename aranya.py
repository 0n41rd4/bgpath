#!/usr/bin/env python3
"""aranya - evidence layer over public internet-infrastructure data.

Phase 1 prototype: fetch every configured source for an IP, keep the raw
responses, and show the parsed result per source.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

import compare
import export
import render

from registry import observe, sources, store
import views

def _default_db() -> str:
    root = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(root, "aranya", "aranya.db")


def _dump_source(directory, source, url, status, body, error, parsed) -> None:
    if not directory:
        return
    source_dir = os.path.join(directory, source)
    os.makedirs(source_dir, exist_ok=True)
    if body is not None:
        with open(os.path.join(source_dir, "output.txt"), "w", encoding="utf-8") as handle:
            handle.write(body)
    meta = {"source": source, "url": url, "status": status, "error": error, "parsed": parsed}
    with open(os.path.join(source_dir, "output.json"), "w", encoding="utf-8") as handle:
        json.dump(meta, handle, ensure_ascii=False, indent=2, sort_keys=True, default=str)


def _link_last(root: str, name: str) -> None:
    os.makedirs(root, exist_ok=True)
    link = os.path.join(root, "last")
    if os.path.lexists(link):
        if os.path.isdir(link) and not os.path.islink(link):
            raise RuntimeError(f"{link} is a directory, refusing to replace it")
        os.unlink(link)
    os.symlink(name, link)


def _update_dbs() -> int:
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "update_geoip.sh")
    if not os.path.isfile(script):
        print(f"update script not found: {script}")
        return 1
    return subprocess.run([script], check=False).returncode


def _print_warnings(test_dir=None) -> None:
    items = sources.warnings()
    if not items:
        return
    print("warnings:", file=sys.stderr)
    for item in items:
        print(f"  ! {item}", file=sys.stderr)
    if test_dir:
        with open(os.path.join(test_dir, "_warnings.txt"), "w", encoding="utf-8") as handle:
            handle.write("\n".join(items) + "\n")


def run_adapter(
    conn,
    adapter: dict,
    ip: str,
    context: dict,
    fetch=None,
    dump_dir=None,
) -> tuple[str, object]:
    store.delete_observations(conn, ip, adapter["id"])
    if "precheck" in adapter:
        reason = adapter["precheck"]()
        if reason:
            status = f"skipped ({reason})"
            store.save_fetch(conn, adapter["id"], adapter["id"], None, None, status, ip)
            _dump_source(dump_dir, adapter["id"], adapter["id"], None, None, status, None)
            return status, None

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
        _dump_source(dump_dir, adapter["id"], sources.redact_url(url), status, body, error, None)
        return f"error ({error})", None

    try:
        parsed, observations = observe.observe(adapter, ip, body)
    except ValueError as exc:
        _dump_source(dump_dir, adapter["id"], sources.redact_url(url), status, body, f"parse error ({exc})", None)
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

    _dump_source(dump_dir, adapter["id"], sources.redact_url(url), status, body, None, parsed)
    return "ok", parsed


def run_all(conn, ip: str, fetch=None, dump_dir=None, verbose: bool = False) -> dict:
    context: dict = {"ip": ip}
    remaining = list(sources.SOURCES)
    statuses: dict[str, str] = {}
    parsed_results: dict[str, object] = {}
    total = len(remaining)
    done = 0
    if verbose:
        print(f"fetching {total} sources for {ip}", file=sys.stderr, flush=True)

    progressed = True
    while remaining and progressed:
        progressed = False
        for adapter in list(remaining):
            if not all(key in context for key in adapter["needs"]):
                continue
            remaining.remove(adapter)
            progressed = True
            started = time.perf_counter()
            status, parsed = run_adapter(conn, adapter, ip, context, fetch, dump_dir)
            statuses[adapter["id"]] = status
            parsed_results[adapter["id"]] = parsed
            done += 1
            if verbose:
                print(
                    f"[{done:>2}/{total}] {adapter['id']:<26} {status:<30} {time.perf_counter() - started:5.1f}s",
                    file=sys.stderr,
                    flush=True,
                )

    for adapter in remaining:
        store.delete_observations(conn, ip, adapter["id"])
        if adapter.get("contextual"):
            status = f"skipped (contextual: needs {', '.join(adapter['needs'])})"
        else:
            status = f"skipped (missing {', '.join(adapter['needs'])})"
        statuses[adapter["id"]] = status
        store.save_fetch(conn, adapter["id"], adapter["id"], None, None, status, ip)
        _dump_source(dump_dir, adapter["id"], adapter["id"], None, None, status, None)
        done += 1
        if verbose:
            print(f"[{done:>2}/{total}] {adapter['id']:<26} {status}", file=sys.stderr, flush=True)

    if dump_dir:
        os.makedirs(dump_dir, exist_ok=True)
        with open(os.path.join(dump_dir, "_status.txt"), "w", encoding="utf-8") as handle:
            handle.write("source\tstatus\tfolder\n")
            for source_id, status in statuses.items():
                handle.write(f"{source_id}\t{status}\t{source_id}/\n")

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
    marks = {"agree": "=", "single": "·", "disagree": "!", "spread": "~"}
    print("\ncomparison:")
    for row in compare.summarize(conn, ip):
        mark = marks[row["verdict"]]
        print(f"  [{mark}] {row['topic']}.{row['key']}  ({row['verdict']})")
        for value, backers in row["values"].items():
            print(f"       {_fmt(json.loads(value))}  <-  {', '.join(backers)}")


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
    sources.load_env()
    parser = argparse.ArgumentParser(description="aranya phase 1 prototype")
    parser.add_argument("ip", nargs="?", help="IP address to look up")
    parser.add_argument("--db", default=os.environ.get("ARANYA_DB") or _default_db(), help="SQLite file (default: %(default)s)")
    parser.add_argument("--view", action="store_true", help="render the claim view for IP (no fetch)")
    parser.add_argument("--normalize", action="store_true", help="compare canonical values (with --view/--report/--stats)")
    parser.add_argument("--entities", action="store_true", help="resolve the IP's ownership entity")
    parser.add_argument("--report", action="store_true", help="cross-IP overview + agreement profile")
    parser.add_argument("--stats", action="store_true", help="cross-IP analysis over the store")
    parser.add_argument("--export", metavar="FILE", help="write the JSON contract (no fetch)")
    parser.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    parser.add_argument("--ips", help="comma-separated IP filter for --export/--html, or IPs to fetch")
    parser.add_argument("--topics", help="comma-separated topic or topic.key filter")
    parser.add_argument("--dump", nargs="?", const="dumps", metavar="DIR", help="write raw per-source output under DIR/<timestamp>/<ip>/")
    parser.add_argument("--update-dbs", action="store_true", help="refresh the local MaxMind/DB-IP databases")
    parser.add_argument("--clear", action="store_true", help="empty the whole database and exit")
    parser.add_argument("--clear-ip", metavar="IP", help="empty just this IP (comma-separated allowed) and exit")
    parser.add_argument("--with-observations", action="store_true", help="embed raw observations in export")
    parser.add_argument("--show-fetch", type=int, metavar="ID", help="print a stored fetch body")
    parser.add_argument("-v", "--verbose", action="store_true", help="show per-source progress on stderr")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = parser.parse_args(argv)

    if args.update_dbs:
        return _update_dbs()

    if args.clear and (args.ip or args.ips):
        parser.error("--clear empties the whole database; use --clear-ip <ip> for a single IP")

    color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    conn = store.open_store(args.db)

    if args.clear:
        totals = store.clear(conn)
        conn.close()
        print(f"cleared {totals['observations']} observations and {totals['fetches']} fetches (all)")
        return 0

    if args.clear_ip:
        targets = [part.strip() for part in args.clear_ip.split(",") if part.strip()]
        totals = {"observations": 0, "fetches": 0}
        for target in targets:
            counts = store.clear(conn, target)
            totals["observations"] += counts["observations"]
            totals["fetches"] += counts["fetches"]
        conn.close()
        print(
            f"cleared {totals['observations']} observations and {totals['fetches']} fetches "
            f"({', '.join(targets)})"
        )
        return 0

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
        print("\n".join(render.overview_view(conn, ips, color, normalize=args.normalize)))
        print("\n".join(render.profile_view(conn, ips, color, normalize=args.normalize)))
        conn.close()
        return 0

    if args.stats:
        ips = [args.ip] if args.ip else None
        print("\n".join(render.stats_view(conn, ips, color, normalize=args.normalize)))
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

    if not args.ip and not args.ips:
        parser.error("an IP is required (or use --report/--export/--html)")

    targets = [part.strip() for part in (args.ips or args.ip).split(",") if part.strip()]
    test_dir = None
    if args.dump:
        name = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        test_dir = os.path.join(args.dump, name)
        os.makedirs(test_dir, exist_ok=True)
        _link_last(args.dump, name)
    _print_warnings(test_dir)
    for target in targets:
        dump_dir = os.path.join(test_dir, target) if test_dir else None
        statuses, _ = run_all(conn, target, dump_dir=dump_dir, verbose=args.verbose)

        print(f"aranya {target}\n")
        print("sources:")
        for adapter in sources.SOURCES:
            print(f"  {statuses[adapter['id']]:<12} {adapter['id']}")

        print_summary(conn, target)
        print_comparison(conn, target)
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
