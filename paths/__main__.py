"""CLI: capture a trace, build the topological graph, optionally enrich it.

    python -m paths trace 8.8.8.8 --flows 4 --enrich
    python -m paths show
    python -m paths topology <run_id>
"""

from __future__ import annotations

import argparse
import os
import time

import paths.enrich as enrich
import paths.export as paths_export
import paths.graph as graphlib
import paths.ingest as ingest
import paths.probe as probe
import paths.store as store

DEFAULT_DB = "paths.db"


def _run_id(target: str) -> str:
    return f"{target}@{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"


def _enrich(conn, run_id, interface, args) -> None:
    stats = enrich.expand(
        conn,
        run_id,
        interface,
        budget=args.budget,
        sessions=not args.no_sessions,
        peeringdb=not args.no_peeringdb,
        neighbours=not args.no_neighbours,
        aliases=not args.no_alias,
        geo=not args.no_geo,
        probes=not args.no_probes,
    )
    print(
        f"  enriched: {stats['origin_edges']} origin edges, {stats['as_edges']} AS edges, "
        f"{stats['facilities']} facilities, {stats['ixps']} IXPs, {len(stats['asns'])} ASes"
    )
    print(
        f"  AS names: {stats['named']}, hops geolocated: {stats['located']}, "
        f"facility coords: {stats['facility_geo']}, ASes with Atlas probes: {stats['probed']}"
    )
    sessions = stats["sessions"]
    print(
        f"  BGP sessions: {sessions['sessions']} over {sessions['collectors']} collectors "
        f"(prefix {sessions['prefix']})"
    )
    if stats["aliased"]:
        print("  IP aliasing (one IP, >1 AS):")
        for ip, asns in stats["aliased"].items():
            print(f"    {ip} -> {', '.join(asns)}")
    else:
        print("  IP aliasing: none observed")
    print(f"  alias resolution: {stats['machines']} machine(s), {stats['clustered']} interfaces clustered")


def _build_interface(conn, run_id):
    interface = graphlib.interface_graph(store.load_hops(conn, run_id))
    store.clear_layer(conn, run_id, "interface")
    graphlib.persist(conn, run_id, interface, layer="interface")
    return interface


def _report_interface(interface) -> None:
    summary = graphlib.summary(interface)
    print(
        f"  interface layer: {summary['nodes']} nodes, {summary['edges']} edges, "
        f"{len(summary['ecmp_nodes'])} ECMP fan-out, {summary['gap_edges']} gap edges"
    )
    for node in summary["ecmp_nodes"]:
        nexts = sorted(interface.successors(node))
        print(f"    ECMP {node} -> {', '.join(nexts)}")


def cmd_trace(args) -> int:
    if args.no_cache:
        os.environ["PATHS_CACHE"] = "off"
    if not probe.available(args.tool):
        print(f"{probe.TOOLS.get(args.tool, args.tool)} not found on PATH")
        return 1
    protocols = tuple(p.strip() for p in args.protocols.split(",") if p.strip())
    try:
        started, hops, meta = probe.run(
            args.target, flows=args.flows, max_ttl=args.maxttl, tool=args.tool, protocols=protocols
        )
    except Exception as exc:
        print(f"capture failed: {exc}")
        return 1
    if not hops:
        print("no hops captured")
        return 1
    run_id = _run_id(args.target)
    conn = store.open_store(args.db)
    store.save_run(
        conn,
        {
            "run_id": run_id,
            "target": args.target,
            "port": 33434,
            "proto": ",".join(protocols),
            "src_ip": meta.get("vantage"),
            "tool": meta.get("tool"),
            "started_at": started,
            "meta": meta,
        },
    )
    store.save_hops(conn, run_id, hops)
    interface = _build_interface(conn, run_id)

    print(f"run {run_id}  vantage {meta.get('vantage')}  flows {meta.get('flow_ids')}  protocols {meta.get('protocols')}")
    _report_interface(interface)
    if args.enrich:
        _enrich(conn, run_id, interface, args)
    conn.close()
    return 0


def cmd_ingest(args) -> int:
    if args.no_cache:
        os.environ["PATHS_CACHE"] = "off"
    try:
        hops = ingest.ingest_hops(args.file, args.tool, args.protocol)
    except Exception as exc:
        print(f"ingest failed: {exc}")
        return 1
    if not hops:
        print("no hops in file")
        return 1
    conn = store.open_store(args.db)
    run_id = args.run_id
    if run_id:
        row = conn.execute("SELECT target FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        target = row[0] if row else args.target
    else:
        target = args.target
        if not target:
            print("--target is required for a new run")
            conn.close()
            return 1
        run_id = _run_id(target)
    if not conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone():
        store.save_run(
            conn,
            {
                "run_id": run_id,
                "target": target,
                "port": None,
                "proto": args.protocol,
                "src_ip": None,
                "tool": args.tool,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "meta": {"tool": args.tool, "protocols": [args.protocol] if args.protocol else []},
            },
        )
    store.save_hops(conn, run_id, hops)
    interface = _build_interface(conn, run_id)
    print(f"run {run_id}  ingested {len(hops)} hops from {args.tool}{'/' + args.protocol if args.protocol else ''}")
    _report_interface(interface)
    if args.enrich:
        _enrich(conn, run_id, interface, args)
    conn.close()
    return 0


def cmd_show(args) -> int:
    conn = store.open_store(args.db)
    runs = conn.execute(
        "SELECT run_id, target, src_ip, started_at, tool FROM runs ORDER BY started_at"
    ).fetchall()
    if not runs:
        print("no runs")
        conn.close()
        return 0
    for run_id, target, src_ip, started_at, tool in runs:
        print(f"{run_id}  target={target}  vantage={src_ip}  {started_at}  {tool}")
        counts = store.graph_counts(conn, run_id)
        for layer, nodes in counts["nodes"].items():
            edges = counts["edges"].get(layer, {})
            print(f"    {layer:<10} {nodes:>4} nodes  {edges.get('distinct', 0):>4} edges")
    conn.close()
    return 0


def cmd_topology(args) -> int:
    conn = store.open_store(args.db)
    rows = conn.execute(
        "SELECT layer, src, dst, ttl, count, min_rtt_ms FROM edges WHERE run_id = ? "
        "ORDER BY CASE layer WHEN 'interface' THEN 0 WHEN 'machine' THEN 1 WHEN 'origin' THEN 2 "
        "WHEN 'as' THEN 3 WHEN 'session' THEN 4 WHEN 'collector' THEN 5 WHEN 'facility' THEN 6 WHEN 'ix' THEN 7 ELSE 8 END, src, dst",
        (args.run_id,),
    ).fetchall()
    if not rows:
        print(f"no edges for run {args.run_id}")
        conn.close()
        return 1
    current = None
    for layer, src, dst, ttl, count, min_rtt in rows:
        if layer != current:
            print(f"[{layer}]")
            current = layer
        rtt = f" {min_rtt:6.1f}ms" if min_rtt is not None else ""
        print(f"  {src:<22} -> {dst:<22} ttl={ttl} flows={count}{rtt}")
    conn.close()
    return 0


def cmd_html(args) -> int:
    conn = store.open_store(args.db)
    run_id = args.run_id
    if not run_id:
        row = conn.execute("SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
        if not row:
            print("no runs")
            conn.close()
            return 1
        run_id = row[0]
    html = paths_export.render_html(conn, run_id)
    out = args.output or f"{run_id.replace('@', '_').replace(':', '')}.html"
    with open(out, "w") as handle:
        handle.write(html)
    print(f"wrote {out}  ({len(html)} bytes)")
    conn.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="paths", description="path & topology exploration")
    parser.add_argument("--db", default=DEFAULT_DB)
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--enrich", action="store_true", help="expand via BGP/PeeringDB sources")
    common.add_argument("--budget", type=int, default=12, help="max interfaces to enrich")
    common.add_argument("--no-sessions", action="store_true", help="skip RouteViews BGP sessions")
    common.add_argument("--no-peeringdb", action="store_true", help="skip PeeringDB facilities/IXPs")
    common.add_argument("--no-neighbours", action="store_true", help="skip RIPEstat AS neighbours")
    common.add_argument("--no-alias", action="store_true", help="skip rDNS alias resolution")
    common.add_argument("--no-geo", action="store_true", help="skip hop geolocation")
    common.add_argument("--no-probes", action="store_true", help="skip RIPE Atlas probe counts")
    common.add_argument("--no-cache", action="store_true", help="bypass the source-analysis disk cache")

    trace = sub.add_parser("trace", parents=[common], help="capture a trace and build the graph")
    trace.add_argument("target")
    trace.add_argument("--tool", choices=["scamper", "dublin"], default="scamper")
    trace.add_argument("--protocols", default="udp", help="comma-separated Paris protocols: udp,icmp,tcp")
    trace.add_argument("--flows", type=int, default=4)
    trace.add_argument("--maxttl", type=int, default=20)
    trace.set_defaults(func=cmd_trace)

    ing = sub.add_parser("ingest", parents=[common], help="ingest traceroute output from another tool")
    ing.add_argument("file")
    ing.add_argument("--tool", choices=list(ingest.TOOLS), required=True)
    ing.add_argument("--protocol", help="protocol label for the ingested hops")
    ing.add_argument("--target", help="target IP (required for a new run)")
    ing.add_argument("--run-id", help="append to an existing run")
    ing.set_defaults(func=cmd_ingest)

    show = sub.add_parser("show", help="list runs and graph sizes")
    show.set_defaults(func=cmd_show)

    topo = sub.add_parser("topology", help="print edges for a run")
    topo.add_argument("run_id")
    topo.set_defaults(func=cmd_topology)

    html = sub.add_parser("html", help="render the graph as self-contained HTML")
    html.add_argument("run_id", nargs="?")
    html.add_argument("-o", "--output")
    html.set_defaults(func=cmd_html)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
