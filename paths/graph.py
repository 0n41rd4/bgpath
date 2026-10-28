"""Topological graph construction from raw hops.

The interface layer is built from observed adjacency inside each flow: hop at
TTL n is adjacent to the next answered hop at TTL m>n. Missing TTLs are bridged
only within the same flow, because that probe traversed the gap; edges are never
mixed across flows. When one flow has several replies at the same TTL, keep the
best RTT for that TTL rather than connecting every reply to every next hop; that
cross-product invents traversals the probe never made. Multiple flows still show
ECMP.
"""

from __future__ import annotations

import ipaddress

try:
    import networkx as nx
except ImportError:
    nx = None

import paths.store as store


def _is_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def interface_graph(hops: list[dict], vantage: str | None = None) -> "nx.DiGraph":
    """Build the interface graph.

    `vantage` is the probe's public egress IP (behind NAT it is not present in
    the raw hops). When given, non-global hops (the private LAN gateway) are
    dropped and `vantage` becomes the origin, connected to the first public hop
    of each flow.
    """
    if nx is None:
        raise RuntimeError("networkx is required for graph building")
    graph = nx.DiGraph()
    if vantage:
        graph.add_node(vantage)
    by_flow: dict[int, list[dict]] = {}
    for hop in hops:
        if not hop.get("src_ip"):
            continue
        if vantage and not _is_global(hop["src_ip"]):
            continue
        by_flow.setdefault(hop["flow_id"], []).append(hop)
    for flow_id, entries in by_flow.items():
        levels: dict[int, dict] = {}
        for hop in entries:
            graph.add_node(hop["src_ip"])
            data = graph.nodes[hop["src_ip"]]
            data.setdefault("protocols", set())
            data.setdefault("tools", set())
            if hop.get("protocol"):
                data["protocols"].add(hop["protocol"])
            if hop.get("tool"):
                data["tools"].add(hop["tool"])
            ttl = hop["ttl"] if hop["ttl"] is not None else 0
            previous = levels.get(ttl)
            if previous is None or (
                hop["rtt_ms"] is not None and (previous["rtt_ms"] is None or hop["rtt_ms"] < previous["rtt_ms"])
            ):
                levels[ttl] = hop
        if vantage and levels:
            min_ttl = min(levels)
            first = levels[min_ttl]
            _add_edge(graph, vantage, first["src_ip"], flow_id, first, min_ttl)
        ttls = sorted(levels)
        for a_ttl, b_ttl in zip(ttls, ttls[1:]):
            previous, current = levels[a_ttl], levels[b_ttl]
            if previous["src_ip"] == current["src_ip"]:
                continue
            _add_edge(graph, previous["src_ip"], current["src_ip"], flow_id, current, b_ttl - a_ttl)
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
        "gap_edges": sum(1 for _, _, data in graph.edges(data=True) if data.get("gap")),
    }
