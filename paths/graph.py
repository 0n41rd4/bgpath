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
        levels: dict[int, dict[str, dict]] = {}
        for hop in entries:
            if not hop.get("src_ip"):
                continue
            graph.add_node(hop["src_ip"])
            data = graph.nodes[hop["src_ip"]]
            data.setdefault("protocols", set())
            data.setdefault("tools", set())
            if hop.get("protocol"):
                data["protocols"].add(hop["protocol"])
            if hop.get("tool"):
                data["tools"].add(hop["tool"])
            ttl = hop["ttl"] if hop["ttl"] is not None else 0
            level = levels.setdefault(ttl, {})
            previous = level.get(hop["src_ip"])
            if previous is None or (
                hop["rtt_ms"] is not None and (previous["rtt_ms"] is None or hop["rtt_ms"] < previous["rtt_ms"])
            ):
                level[hop["src_ip"]] = hop
        ttls = sorted(levels)
        for a_ttl, b_ttl in zip(ttls, ttls[1:]):
            span = b_ttl - a_ttl
            sources = list(levels[a_ttl].values())[:16]
            for current in list(levels[b_ttl].values())[:16]:
                for previous in sources:
                    _add_edge(graph, previous["src_ip"], current["src_ip"], flow_id, current, span)
    return graph


def _add_edge(graph: nx.DiGraph, src: str, dst: str, flow_id: int, hop: dict, span: int) -> None:
    protocol = hop.get("protocol")
    tool = hop.get("tool")
    if graph.has_edge(src, dst):
        data = graph[src][dst]
        data["count"] += 1
        if flow_id is not None:
            data["flows"].add(flow_id)
        data["span"] = min(data["span"], span)
        data["gap"] = data["span"] > 1
        if protocol:
            data["protocols"].add(protocol)
        if tool:
            data["tools"].add(tool)
        if hop["rtt_ms"] is not None:
            data["min_rtt_ms"] = min(data["min_rtt_ms"], hop["rtt_ms"]) if data["min_rtt_ms"] is not None else hop["rtt_ms"]
        if hop["ttl"] is not None:
            data["ttl"] = min(data["ttl"], hop["ttl"]) if data["ttl"] is not None else hop["ttl"]
    else:
        graph.add_edge(
            src,
            dst,
            count=1,
            flows={flow_id} if flow_id is not None else set(),
            protocols={protocol} if protocol else set(),
            tools={tool} if tool else set(),
            span=span,
            gap=span > 1,
            min_rtt_ms=hop["rtt_ms"],
            ttl=hop["ttl"],
        )


def ecmp_nodes(graph: nx.DiGraph) -> list[str]:
    result: list[str] = []
    for node in graph.nodes:
        nexts = {
            dst
            for _, dst, data in graph.out_edges(node, data=True)
            if not data.get("gap")
        }
        if len(nexts) > 1:
            result.append(node)
    return sorted(result)


def _sorted_sets(data: dict) -> dict:
    return {key: sorted(value) for key, value in data.items() if isinstance(value, set)}


def persist(conn, run_id: str, graph: nx.DiGraph, layer: str = "interface") -> None:
    for node in graph.nodes:
        store.add_node(conn, layer, node, _sorted_sets(graph.nodes[node]))
    for src, dst, data in graph.edges(data=True):
        store.add_edge(
            conn,
            run_id,
            layer,
            src,
            dst,
            ttl=data.get("ttl"),
            rtt_ms=data.get("min_rtt_ms"),
            attrs={
                "flows": sorted(data.get("flows") or [], key=lambda value: (value is None, value)),
                "protocols": sorted(data.get("protocols") or []),
                "tools": sorted(data.get("tools") or []),
                "gap": data.get("gap"),
                "span": data.get("span"),
                "count": data.get("count"),
            },
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
