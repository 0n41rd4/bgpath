"""Topological graph construction from raw hops.

The interface layer is built from observed adjacency inside each flow: hop at
TTL n is adjacent to the next answered hop at TTL m>n. Multiple flow IDs hitting
the same TTL with different replies become a diamond (ECMP) rather than a line.
Unanswered TTLs are kept as gaps (an edge's ttl span > 1), never invented away.
"""

from __future__ import annotations

try:
    import networkx as nx
except ImportError:
    nx = None

import paths.store as store


def interface_graph(hops: list[dict]) -> "nx.DiGraph":
    if nx is None:
        raise RuntimeError("networkx is required for graph building")
    graph = nx.DiGraph()
    by_flow: dict[int, list[dict]] = {}
    for hop in hops:
        by_flow.setdefault(hop["flow_id"], []).append(hop)
    for flow_id, entries in by_flow.items():
        answered = sorted(
            (hop for hop in entries if hop.get("src_ip")),
            key=lambda hop: hop["ttl"] if hop["ttl"] is not None else 0,
        )
        for hop in answered:
            graph.add_node(hop["src_ip"])
        for previous, current in zip(answered, answered[1:]):
            gap = bool(
                previous["ttl"] is not None
                and current["ttl"] is not None
                and current["ttl"] - previous["ttl"] > 1
            )
            _add_edge(graph, previous["src_ip"], current["src_ip"], flow_id, current, gap)
    return graph


def _add_edge(graph: nx.DiGraph, src: str, dst: str, flow_id: int, hop: dict, gap: bool) -> None:
    if graph.has_edge(src, dst):
        data = graph[src][dst]
        data["count"] += 1
        data["flows"].add(flow_id)
        data["gap"] = data["gap"] or gap
        if hop["rtt_ms"] is not None:
            data["min_rtt_ms"] = min(data["min_rtt_ms"], hop["rtt_ms"]) if data["min_rtt_ms"] is not None else hop["rtt_ms"]
        if hop["ttl"] is not None:
            data["ttl"] = min(data["ttl"], hop["ttl"]) if data["ttl"] is not None else hop["ttl"]
    else:
        graph.add_edge(
            src,
            dst,
            count=1,
            flows={flow_id},
            gap=gap,
            min_rtt_ms=hop["rtt_ms"],
            ttl=hop["ttl"],
        )


def ecmp_nodes(graph: nx.DiGraph) -> list[str]:
    return sorted(node for node, degree in graph.out_degree() if degree > 1)


def persist(conn, run_id: str, graph: nx.DiGraph, layer: str = "interface") -> None:
    for node in graph.nodes:
        store.add_node(conn, layer, node)
    for src, dst, data in graph.edges(data=True):
        store.add_edge(
            conn,
            run_id,
            layer,
            src,
            dst,
            ttl=data.get("ttl"),
            rtt_ms=data.get("min_rtt_ms"),
            attrs={"flows": sorted(data.get("flows") or []), "gap": data.get("gap"), "count": data.get("count")},
        )
    store.commit(conn)


def summary(graph: nx.DiGraph) -> dict:
    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "ecmp_nodes": ecmp_nodes(graph),
        "sources": sorted(node for node, degree in graph.in_degree() if degree == 0),
        "sinks": sorted(node for node, degree in graph.out_degree() if degree == 0),
        "gap_edges": sum(1 for _, _, data in graph.edges(data=True) if data.get("gap")),
    }
