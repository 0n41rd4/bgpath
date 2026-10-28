"""CLI: ping + traceroute a target with every available tool, then render HTML.

    python -m paths trace 41.222.2.1              # runs all tools, writes 41.222.2.1.html
    python -m paths trace 41.222.2.1 --tools mtr,traceroute
    python -m paths ingest mtr.json --tool mtr --target 41.222.2.1
    python -m paths show
    python -m paths html --target 41.222.2.1 -o paths.html
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.request

import paths.analysis as analysis
import paths.enrich as enrich
import paths.export as paths_export
import paths.graph as graphlib
import paths.ingest as ingest
import paths.probe as probe
import paths.store as store
import registry.sources as sources

DEFAULT_DB = "paths.db"

NATIVE_TOOLS = ("scamper", "dublin", "voyage")
TOOL_TIMEOUTS = {"scamper": 180, "dublin": 180, "voyage": 300, "mtr": 120, "traceroute": 120}
ALL_TOOLS = ("mtr", "traceroute") + NATIVE_TOOLS
RETRY_TTL = 64


def _run_id(target: str) -> str:
    return f"{target}@{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.{os.urandom(2).hex()}"


def get_public_ip() -> str | None:
    """Public egress IP via an external echo service (NAT hides it locally)."""
    for url in ("https://api.ipify.org", "https://ifconfig.me", "https://ipv4.icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                ip = response.read().decode("utf-8", "replace").strip()
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
                return ip
        except Exception:
            continue
    return None


def _build_interface(conn, run_id, vantage=None):
    graph = graphlib.interface_graph(store.load_hops(conn, run_id), vantage=vantage)
    store.clear_layer(conn, run_id, "interface")
    graphlib.persist(conn, run_id, graph)
    return graph


def _available_tools() -> list[str]:
    return [tool for tool in ALL_TOOLS if probe.available(tool)]


def _resolve_tools(tools_arg: str | None, exclude_arg: str | None) -> list[str]:
    tools = [p.strip() for p in tools_arg.split(",") if p.strip()] if tools_arg else list(_available_tools())
    if exclude_arg:
        drop = {p.strip() for p in exclude_arg.split(",") if p.strip()}
        tools = [tool for tool in tools if tool not in drop]
    return tools


def _observed(hops: list[dict]) -> int:
    return sum(1 for hop in hops if hop.get("src_ip"))


def _should_retry_ttl(hops: list[dict], target: str, maxttl: int) -> bool:
    """Retry only when a trace hit its TTL cap without reaching the target."""
    if maxttl >= RETRY_TTL or not hops:
        return False
    if any(hop.get("src_ip") == target for hop in hops):
        return False
    ttls = [hop["ttl"] for hop in hops if hop.get("src_ip") and hop.get("ttl") is not None]
    return bool(ttls) and max(ttls) >= maxttl


def _capture_tool(tool, target, flows, maxttl, protocols):
    if tool in NATIVE_TOOLS:
        return probe.run(target, flows=flows, max_ttl=maxttl, tool=tool, protocols=protocols)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if tool == "mtr":
        hops = ingest.capture_mtr(target)
        meta = {"tool": "mtr", "protocols": ["icmp"], "flows": 1, "max_ttl": maxttl,
                "flow_ids": sorted({hop["flow_id"] for hop in hops if hop["flow_id"] is not None})}
    elif tool == "traceroute":
        hops = ingest.capture_traceroute(target, max_ttl=maxttl)
        meta = {"tool": "traceroute", "protocols": [], "flows": 1, "max_ttl": maxttl,
                "flow_ids": sorted({hop["flow_id"] for hop in hops if hop["flow_id"] is not None})}
    else:
        raise RuntimeError(f"unknown tool: {tool}")
    return started, hops, meta


def destination_summary(target: str, db: str | None = None, verbose: bool = False) -> dict:
    """Run the `aranya <IP>` lookup on the destination and reduce it to a header.

    Reuses the main aranya pipeline (`aranya.run_all`) and the report's claim
    aggregation (`report.aggregate.cell_summaries`) so the path report shows the
    same facts the standalone lookup does. The lookup always targets the aranya
    <IP> database (`ARANYA_DB` / `~/.local/share/aranya/aranya.db`), independent
    of the paths store, so both tools share the same observations.
    """
    import aranya
    from registry import store as raw_store
    from report import aggregate, asn as asn_report

    sources.load_env()
    conn = raw_store.open_store(db or aranya._default_db())
    try:
        aranya.run_all(conn, target, verbose=verbose)
        summaries = aggregate.cell_summaries(conn, target)
        location = _destination_location(conn, target)
        routing = asn_report.routing_summary(conn, target)
    finally:
        conn.close()

    dest_asn = _consensus_of(summaries, "ownership", "asn") or routing.get("origin_asn")
    upstream = routing.get("upstream_as")
    announced = routing.get("announced")
    observers = routing.get("observers") or []

    by = {(summary["topic"], summary["key"]): summary for summary in summaries}

    def consensus(topic, key):
        summary = by.get((topic, key))
        return summary["consensus"] if summary else None

    loc_summary = by.get(("location", "claim"))
    location_values = 0
    location_labels: list[str] = []
    if loc_summary:
        location_values = sum(loc_summary.get("counts", {}).values()) or len(loc_summary.get("labels", []))
        location_labels = [label["label"] for label in loc_summary.get("labels", [])]

    return {
        "ip": target,
        "location": location or consensus("location", "claim"),
        "location_verdict": loc_summary["verdict_label"] if loc_summary else None,
        "anycast_like": len(location_labels) > 1,
        "location_values": location_values,
        "location_labels": location_labels,
        "prefix": consensus("ownership", "prefix"),
        "asn": dest_asn,
        "name": consensus("ownership", "holder") or consensus("ownership", "name"),
        "rpki": consensus("routing", "rpki"),
        "announced": announced,
        "upstream_as": upstream,
        "observers": observers,
    }


def _consensus_of(summaries: list[dict], topic: str, key: str) -> str | None:
    for summary in summaries:
        if summary["topic"] == topic and summary["key"] == key:
            return summary["consensus"]
    return None


def _destination_location(conn, ip: str) -> str | None:
    """Prefer a city+country, then a country, over bare coordinates."""
    city_country = None
    country_only = None
    for _source, _key, value in conn.execute(
        "SELECT source, key, value FROM v_observations WHERE ip = ? AND topic = 'location'", (ip,)
    ):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            continue
        city = value.get("city")
        country = value.get("country")
        if city and country and city_country is None:
            city_country = f"{city}, {country}"
        elif country and not city and country_only is None:
            country_only = country
    return city_country or country_only


def run_target(
    target: str,
    tools: list[str] | None = None,
    flows: int = 4,
    maxttl: int = 32,
    protocols: tuple[str, ...] = ("udp",),
    db: str = DEFAULT_DB,
    output: str | None = None,
    do_enrich: bool = True,
    no_cache: bool = False,
    text: bool = False,
    do_dest: bool = True,
    verbose: bool = False,
) -> int:
    if no_cache:
        os.environ["PATHS_CACHE"] = "off"

    dest: dict | None = None
    if do_dest:
        try:
            print(f"aranya lookup: {target}")
            dest = destination_summary(target, verbose=verbose)
            bits = [target]
            if dest.get("name"):
                bits.append(f"{dest['name']}" + (f" (AS{dest['asn']})" if dest.get("asn") else ""))
            if dest.get("prefix"):
                bits.append(dest["prefix"])
            if dest.get("location"):
                bits.append(dest["location"])
            print("  " + " · ".join(bits))
        except Exception as exc:
            print(f"  destination lookup failed: {exc}")
            dest = None

    dest_asn = str(dest["asn"]) if dest and dest.get("asn") else None

    tools = tools if tools is not None else _available_tools()
    if not tools:
        print("no traceroute tools available (scamper/dublin/voyage/mtr/traceroute)")
        return 1

    ping = probe.capture_ping(target)
    if ping is None:
        print("  ping: unavailable (tracing anyway)")
    elif ping["reachable"]:
        print(f"  ping: ok  avg {ping['rtt_avg_ms']} ms  loss {ping['loss_percent']}%")
    else:
        print(f"  ping: unreachable  loss {ping['loss_percent']}% (tracing anyway)")

    conn = store.open_store(db)
    public_ip = None
    try:
        public_ip = get_public_ip()
        if public_ip:
            print(f"  public IP: {public_ip}")
    except Exception:
        public_ip = None
    run_ids: list[str] = []
    for tool in tools:
        if verbose:
            print(
                f"  {tool}: probing (timeout {TOOL_TIMEOUTS.get(tool, '?')}s) ...",
                file=sys.stderr,
                flush=True,
            )
        try:
            started, hops, meta = _capture_tool(tool, target, flows, maxttl, protocols)
        except Exception as exc:
            print(f"  {tool}: skipped ({exc})")
            continue
        if tool != "mtr" and _should_retry_ttl(hops, target, maxttl):
            print(f"  {tool}: stopped at TTL {maxttl}; retrying once with {RETRY_TTL}")
            try:
                retry_started, retry_hops, retry_meta = _capture_tool(
                    tool, target, flows, RETRY_TTL, protocols
                )
            except Exception as exc:
                print(f"  {tool}: retry skipped ({exc})")
            else:
                reached = any(hop.get("src_ip") == target for hop in retry_hops)
                if retry_hops and (reached or _observed(retry_hops) > _observed(hops)):
                    started, hops, meta = retry_started, retry_hops, retry_meta
                    meta["retry_ttl"] = RETRY_TTL
        if not hops:
            print(f"  {tool}: no hops")
            continue
        meta["ping"] = ping
        meta["vantage"] = public_ip or meta.get("vantage")
        meta["dest_asn"] = dest_asn
        run_id = _run_id(target)
        store.save_run(
            conn,
            {"run_id": run_id, "target": target, "src_ip": meta.get("vantage"),
             "tool": meta.get("tool", tool), "started_at": started, "meta": meta},
        )
        store.save_hops(conn, run_id, hops)
        graph = _build_interface(conn, run_id, vantage=public_ip)
        summary = graphlib.summary(graph)
        reach = analysis.reachability(hops, target)
        status = "reached" if reach["reached"] else "not reached"
        print(f"  {tool}: {summary['nodes']} nodes, {summary['edges']} edges ({status})")
        if do_enrich:
            stats = enrich.expand(conn, run_id, graph, target)
            print(f"      enriched: {len(stats['asns'])} ASes, {stats['handoffs']} inter-AS handoffs")
        run_ids.append(run_id)

    if not run_ids:
        conn.close()
        print("no runs captured")
        return 1

    if text:
        conn.close()
        return 0

    html = paths_export.render_html(conn, run_ids, dest=dest)
    conn.close()
    out = output or f"{target}.html"
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(html)
    print(f"wrote {out}  ({len(run_ids)} graph(s))")
    return 0


def cmd_trace(args) -> int:
    tools = _resolve_tools(args.tools, args.exclude)
    protocols = tuple(part.strip() for part in args.protocols.split(",") if part.strip())
    return run_target(
        args.target,
        tools=tools,
        flows=args.flows,
        maxttl=args.maxttl,
        protocols=protocols,
        db=args.db,
        output=args.output,
        do_enrich=not args.no_enrich,
        no_cache=args.no_cache,
        text=args.text,
        do_dest=not args.no_dest,
        verbose=args.verbose,
    )


def cmd_ingest(args) -> int:
    if args.no_cache:
        os.environ["PATHS_CACHE"] = "off"
    conn = store.open_store(args.db)
    try:
        hops = ingest.ingest_hops(args.file, args.tool, args.protocol, args.target)
    except Exception as exc:
        print(f"ingest failed: {exc}")
        conn.close()
        return 1
    if not hops:
        print("no hops in file")
        conn.close()
        return 1
    run_id = _run_id(args.target)
    store.save_run(
        conn,
        {"run_id": run_id, "target": args.target, "src_ip": args.vantage, "tool": args.tool,
         "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "meta": {"tool": args.tool, "protocols": [args.protocol] if args.protocol else []}},
    )
    store.save_hops(conn, run_id, hops)
    graph = _build_interface(conn, run_id)
    reach = analysis.reachability(hops, args.target)
    status = "reached" if reach["reached"] else "not reached"
    print(f"run {run_id}  ingested {len(hops)} hops from {args.tool} ({status})")
    if not args.no_enrich:
        stats = enrich.expand(conn, run_id, graph, args.target)
        print(f"  enriched: {len(stats['asns'])} ASes, {stats['handoffs']} inter-AS handoffs")
    conn.close()
    return 0


def cmd_show(args) -> int:
    conn = store.open_store(args.db)
    runs = conn.execute(
        "SELECT run_id, target, src_ip, tool, started_at, meta FROM runs ORDER BY started_at"
    ).fetchall()
    if not runs:
        print("no runs")
        conn.close()
        return 0
    for run_id, target, src_ip, tool, started_at, meta in runs:
        meta = json.loads(meta or "{}")
        ping = meta.get("ping")
        p = ""
        if ping:
            p = "  ping=" + ("ok" if ping.get("reachable") else "unreachable")
        print(f"{run_id}  target={target}  tool={tool}  vantage={src_ip}  {started_at}{p}")
        counts = store.graph_counts(conn, run_id)
        nodes = counts["nodes"].get("interface", 0)
        edges = counts["edges"].get("interface", {}).get("distinct", 0)
        print(f"    interface: {nodes} nodes, {edges} edges")
    conn.close()
    return 0


def cmd_html(args) -> int:
    conn = store.open_store(args.db)
    run_ids = list(args.run_id or [])
    if not run_ids and args.target:
        rows = conn.execute(
            "SELECT run_id, tool FROM runs WHERE target = ? ORDER BY started_at", (args.target,)
        ).fetchall()
        latest: dict[str, str] = {}
        for run_id, tool in rows:
            latest[tool or "?"] = run_id
        run_ids = list(latest.values())
    if not run_ids:
        row = conn.execute("SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
        if not row:
            print("no runs")
            conn.close()
            return 1
        run_ids = [row[0]]
    html = paths_export.render_html(conn, run_ids)
    out = args.output or f"{run_ids[0].replace('@', '_')}.html"
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(html)
    print(f"wrote {out}  ({len(html)} bytes, {len(run_ids)} graph(s))")
    conn.close()
    return 0


def cmd_clear(args) -> int:
    conn = store.open_store(args.db)
    try:
        if args.target:
            counts = store.clear(conn, args.target)
            suffix = f" ({args.target})"
        else:
            counts = store.clear(conn)
            suffix = " (all)"
    finally:
        conn.close()
    print(
        f"cleared {counts['runs']} runs, {counts['hops']} hops, {counts['edges']} edges, "
        f"{counts['nodes']} nodes, {counts['fetches']} fetches{suffix}"
    )
    return 0


def run_path(argv: list[str] | None = None) -> int:
    sources.load_env()
    parser = argparse.ArgumentParser(prog="aranya path", description="ping + traceroute a target and render HTML")
    parser.add_argument("target", nargs="?", help="destination IP")
    parser.add_argument("--tools", help="comma-separated: mtr,traceroute,scamper,dublin,voyage (default: all available)")
    parser.add_argument("--exclude", help="comma-separated tools to drop from the default set")
    parser.add_argument("--flows", type=int, default=4)
    parser.add_argument("--maxttl", type=int, default=32)
    parser.add_argument("--protocols", default="udp", help="comma-separated Paris protocols: udp,icmp,tcp")
    parser.add_argument("--db", default=DEFAULT_DB, help="paths SQLite file")
    parser.add_argument("-o", "--output", help="HTML output path (default <target>.html)")
    parser.add_argument("--no-enrich", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--no-dest", action="store_true", help="skip the aranya lookup of the destination")
    parser.add_argument("-v", "--verbose", action="store_true", help="show per-source progress on stderr")
    parser.add_argument("--text", action="store_true", help="print the text summary instead of HTML")
    parser.add_argument("--clear", nargs="?", const="", metavar="TARGET", help="empty the whole paths DB (or just TARGET) and exit")
    args = parser.parse_args(argv)
    if args.clear is not None:
        if args.target:
            parser.error("--clear takes the target as its argument; e.g. --clear 8.8.8.8")
        targets = [part.strip() for part in args.clear.split(",") if part.strip()]
        conn = store.open_store(args.db)
        try:
            totals = {"runs": 0, "hops": 0, "edges": 0, "nodes": 0, "fetches": 0}
            if targets:
                for target in targets:
                    counts = store.clear(conn, target)
                    totals = {key: totals[key] + counts[key] for key in totals}
                suffix = f" ({', '.join(targets)})"
            else:
                totals = store.clear(conn)
                suffix = " (all)"
        finally:
            conn.close()
        print(
            f"cleared {totals['runs']} runs, {totals['hops']} hops, {totals['edges']} edges, "
            f"{totals['nodes']} nodes, {totals['fetches']} fetches{suffix}"
        )
        return 0
    if not args.target:
        parser.error("a target is required unless --clear is used")
    tools = _resolve_tools(args.tools, args.exclude)
    protocols = tuple(part.strip() for part in args.protocols.split(",") if part.strip())
    return run_target(
        args.target,
        tools=tools,
        flows=args.flows,
        maxttl=args.maxttl,
        protocols=protocols,
        db=args.db,
        output=args.output,
        do_enrich=not args.no_enrich,
        no_cache=args.no_cache,
        text=args.text,
        do_dest=not args.no_dest,
        verbose=args.verbose,
    )


def main(argv: list[str] | None = None) -> int:
    sources.load_env()
    parser = argparse.ArgumentParser(prog="paths", description="path & topology exploration")
    parser.add_argument("--db", default=DEFAULT_DB)
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-enrich", action="store_true", help="skip AS/facility/BGP enrichment")
    common.add_argument("--no-cache", action="store_true", help="bypass the source-analysis disk cache")

    trace = sub.add_parser("trace", parents=[common], help="ping + traceroute (all tools) then render HTML")
    trace.add_argument("target")
    trace.add_argument("--tools", help="comma-separated tools (default: all available)")
    trace.add_argument("--exclude", help="comma-separated tools to drop from the default set")
    trace.add_argument("--protocols", default="udp", help="comma-separated Paris protocols: udp,icmp,tcp")
    trace.add_argument("--flows", type=int, default=4)
    trace.add_argument("--maxttl", type=int, default=32)
    trace.add_argument("-o", "--output", help="HTML output path (default <target>.html)")
    trace.add_argument("--text", action="store_true", help="print text summary instead of HTML")
    trace.add_argument("--no-dest", action="store_true", help="skip the aranya lookup of the destination")
    trace.add_argument("-v", "--verbose", action="store_true", help="show per-source progress on stderr")
    trace.set_defaults(func=cmd_trace)

    ing = sub.add_parser("ingest", parents=[common], help="ingest traceroute output from another tool")
    ing.add_argument("file")
    ing.add_argument("--tool", choices=list(ingest.TOOLS), required=True)
    ing.add_argument("--protocol", help="protocol label for the ingested hops")
    ing.add_argument("--target", required=True, help="target IP")
    ing.add_argument("--vantage", help="source IP this trace ran from")
    ing.set_defaults(func=cmd_ingest)

    show = sub.add_parser("show", help="list runs")
    show.set_defaults(func=cmd_show)

    clear = sub.add_parser("clear", help="empty the paths database (or one target)")
    clear.add_argument("target", nargs="?", help="destination IP to remove; omit to remove everything")
    clear.set_defaults(func=cmd_clear)

    html = sub.add_parser("html", help="render graph(s) as self-contained HTML")
    html.add_argument("run_id", nargs="*", help="run id(s); omit with --target for one graph per tool")
    html.add_argument("--target", help="render the latest run per tool for this target")
    html.add_argument("-o", "--output")
    html.set_defaults(func=cmd_html)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
