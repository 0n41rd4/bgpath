"""CLI: capture a trace, build the topological graph, optionally enrich it.

    python -m paths trace 8.8.8.8 --flows 4 --enrich
    python -m paths show
    python -m paths topology <run_id>
"""

from __future__ import annotations

import argparse
import time

import paths.enrich as enrich
import paths.graph as graphlib
import paths.probe as probe
import paths.store as store

DEFAULT_DB = "paths.db"


def _run_id(target: str) -> str:
    return f"{target}@{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"


def cmd_trace(args) -> int:
    if not probe.available(args.tool):
        print(f"{probe.TOOLS.get(args.tool, args.tool)} not found on PATH")
        return 1
    try:
        started, hops, meta = probe.run(
            args.target, flows=args.flows, max_ttl=args.maxttl, tool=args.tool
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
            "proto": "udp",
            "src_ip": meta.get("vantage"),
            "tool": meta.get("tool"),
            "started_at": started,
            "meta": meta,
        },
    )
    store.save_hops(conn, run_id, hops)

    interface = graphlib.interface_graph(hops)
    graphlib.persist(conn, run_id, interface, layer="interface")

    summary = graphlib.summary(interface)
    print(f"run {run_id}  vantage {meta.get('vantage')}  flows {meta.get('flow_ids')}")
    print(
        f"  interface layer: {summary['nodes']} nodes, {summary['edges']} edges, "
        f"{len(summary['ecmp_nodes'])} ECMP fan-out, {summary['gap_edges']} gap edges"
    )
    if summary["ecmp_nodes"]:
        for node in summary["ecmp_nodes"]:
            nexts = sorted(interface.successors(node))
            print(f"    ECMP {node} -> {', '.join(nexts)}")

    if args.enrich:
        stats = enrich.expand(conn, run_id, interface, budget=args.budget)
        print(
            f"  enriched: {stats['origin_edges']} origin edges, {stats['as_edges']} AS edges, "
            f"{stats['facilities']} facilities, {stats['ixps']} IXPs, {len(stats['asns'])} ASes"
        )
        print(f"  ASes: {', '.join(stats['asns'])}")

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
        "ORDER BY CASE layer WHEN 'interface' THEN 0 WHEN 'origin' THEN 1 WHEN 'as' THEN 2 "
        "WHEN 'facility' THEN 3 WHEN 'ix' THEN 4 ELSE 5 END, src, dst",
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="paths", description="path & topology exploration")
    parser.add_argument("--db", default=DEFAULT_DB)
    sub = parser.add_subparsers(dest="command", required=True)

    trace = sub.add_parser("trace", help="capture a trace and build the graph")
    trace.add_argument("target")
    trace.add_argument("--tool", choices=["scamper", "dublin"], default="scamper")
    trace.add_argument("--flows", type=int, default=4)
    trace.add_argument("--maxttl", type=int, default=20)
    trace.add_argument("--enrich", action="store_true", help="expand via BGP/PeeringDB sources")
    trace.add_argument("--budget", type=int, default=12, help="max interfaces to enrich")
    trace.set_defaults(func=cmd_trace)

    show = sub.add_parser("show", help="list runs and graph sizes")
    show.set_defaults(func=cmd_show)

    topo = sub.add_parser("topology", help="print edges for a run")
    topo.add_argument("run_id")
    topo.set_defaults(func=cmd_topology)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
