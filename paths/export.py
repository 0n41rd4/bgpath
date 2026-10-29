"""Render runs as a self-contained HTML graph.

One graph per run, and since each run is a single traceroute tool, one graph per
tool. Visual edges are packet traversal only; inter-AS edges carry a clickable
`handoff` (shared facilities/IXPs and whether the outgoing AS advertises the
destination). A run that never reached the target just ends at its last hop.
"""

from __future__ import annotations

import json
from pathlib import Path

import paths.analysis as analysis

TEMPLATE = Path(__file__).parent / "template.html"

COL_GAP = 190
ROW_GAP = 70
ORIGIN_X = 20
ORIGIN_Y = 20


def _run(conn, run_id: str) -> dict:
    row = conn.execute(
        "SELECT run_id, target, src_ip, tool, started_at, meta FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if not row:
        return {"run_id": run_id}
    return {
        "run_id": row[0],
        "target": row[1],
        "vantage": row[2],
        "tool": row[3],
        "started_at": row[4],
        "meta": json.loads(row[5] or "{}"),
    }


def _nodes(conn) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for key, layer, attrs in conn.execute("SELECT key, layer, attrs FROM nodes"):
        out[key] = {"layer": layer, **(json.loads(attrs or "{}"))}
    return out


def _edges(conn, run_id: str) -> list[dict]:
    out: list[dict] = []
    for src, dst, ttl, count, min_rtt, attrs in conn.execute(
        "SELECT src, dst, ttl, count, min_rtt_ms, attrs FROM edges WHERE run_id = ? AND layer = 'interface'",
        (run_id,),
    ):
        data = json.loads(attrs or "{}")
        out.append(
            {
                "source": src,
                "target": dst,
                "ttl": ttl,
                "count": count,
                "min_rtt_ms": min_rtt,
                "attrs": data,
            }
        )
    return out


def _hop_ttl(conn, run_id: str) -> dict[str, int]:
    rows = conn.execute(
        "SELECT src_ip, MIN(ttl) FROM hops WHERE run_id = ? AND src_ip IS NOT NULL GROUP BY src_ip",
        (run_id,),
    ).fetchall()
    return {ip: ttl for ip, ttl in rows}


def _hop_rtt(conn, run_id: str) -> dict[str, float]:
    rows = conn.execute(
        "SELECT src_ip, MIN(rtt_ms) FROM hops WHERE run_id = ? AND src_ip IS NOT NULL GROUP BY src_ip",
        (run_id,),
    ).fetchall()
    return {ip: rtt for ip, rtt in rows if rtt is not None}


def _raw_hops(conn, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT flow_id, ttl, src_ip, rtt_ms, icmp_type, icmp_code, reply_ttl, ip_id, "
        "nat_id, mpls, is_last, name, protocol, tool "
        "FROM hops WHERE run_id = ? ORDER BY flow_id, ttl, id",
        (run_id,),
    ).fetchall()
    return [
        {
            "flow_id": flow,
            "ttl": ttl,
            "src_ip": ip,
            "rtt_ms": rtt,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "reply_ttl": reply_ttl,
            "ip_id": ip_id,
            "nat_id": nat_id,
            "mpls": json.loads(mpls or "[]"),
            "is_last": bool(last),
            "name": name,
            "protocol": protocol,
            "tool": tool,
        }
        for flow, ttl, ip, rtt, icmp_type, icmp_code, reply_ttl, ip_id, nat_id, mpls, last, name, protocol, tool in rows
    ]


def _fetches(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT ip, source, url, status, error, body, fetched_at FROM fetches ORDER BY id"
    ).fetchall()
    return [
        {"ip": ip, "source": source, "url": url, "status": status,
         "error": error, "body": body, "fetched_at": fetched_at}
        for ip, source, url, status, error, body, fetched_at in rows
    ]


def build(conn, run_id: str) -> dict:
    run = _run(conn, run_id)
    target = run.get("target")
    nodes = _nodes(conn)
    edges = _edges(conn, run_id)
    hop_ttl = _hop_ttl(conn, run_id)
    rtt = _hop_rtt(conn, run_id)
    raw = _raw_hops(conn, run_id)
    fetch_by_ip: dict[str, list[dict]] = {}
    for fetch in _fetches(conn):
        ip = fetch.get("ip")
        if ip:
            fetch_by_ip.setdefault(ip, []).append(fetch)
    endpoints = {edge["source"] for edge in edges} | {edge["target"] for edge in edges}
    vantage = run.get("vantage")
    ttl = {vantage: 0} if vantage else {}
    for ip, value in hop_ttl.items():
        if ip in endpoints:
            ttl[ip] = value

    columns: dict[int, list[str]] = {}
    for ip in ttl:
        columns.setdefault(ttl[ip], []).append(ip)
    position: dict[str, tuple[float, float]] = {}
    for col, ttl_value in enumerate(sorted(columns)):
        members = sorted(columns[ttl_value])
        for row, ip in enumerate(members):
            position[ip] = (ORIGIN_X + row * COL_GAP, ORIGIN_Y + col * ROW_GAP)

    mpls_by_ip: dict[str, list] = {}
    for hop in raw:
        labels = hop.get("mpls") or []
        if labels:
            mpls_by_ip.setdefault(hop["src_ip"], [])
            for label in labels:
                if label not in mpls_by_ip[hop["src_ip"]]:
                    mpls_by_ip[hop["src_ip"]].append(label)

    hops = []
    for ip in sorted(position, key=lambda value: (ttl.get(value, 0), value)):
        x, y = position[ip]
        attrs = nodes.get(ip, {})
        hops.append(
            {
                "id": ip,
                "ttl": ttl.get(ip),
                "x": x,
                "y": y,
                "asn": attrs.get("asn"),
                "as_name": attrs.get("as_name"),
                "atlas_probes": attrs.get("atlas_probes"),
                "atlas_anchors": attrs.get("atlas_anchors"),
                "atlas_connected": attrs.get("atlas_connected"),
                "atlas_traceroutes": attrs.get("atlas_traceroutes"),
                "prefix": attrs.get("prefix"),
                "country": attrs.get("country"),
                "city": attrs.get("city"),
                "latitude": attrs.get("latitude"),
                "longitude": attrs.get("longitude"),
                "hostname": attrs.get("hostname"),
                "ixp": attrs.get("ixp"),
                "bgp_asn": attrs.get("bgp_asn"),
                "bgp_prefix": attrs.get("bgp_prefix"),
                "bgp_country": attrs.get("bgp_country"),
                "bgp_name": attrs.get("bgp_name"),
                "mpls": mpls_by_ip.get(ip, []),
                "is_target": ip == target,
                "rtt_ms": rtt.get(ip),
                "provenance": fetch_by_ip.get(ip, []),
            }
        )

    out_edges = []
    for edge in edges:
        src, dst = edge["source"], edge["target"]
        if src not in position or dst not in position:
            continue
        attrs = edge["attrs"]
        handoff = attrs.get("handoff")
        out_edges.append(
            {
                "source": src,
                "target": dst,
                "gap": bool(attrs.get("gap")),
                "span": attrs.get("span"),
                "from_as": nodes.get(src, {}).get("asn"),
                "to_as": nodes.get(dst, {}).get("asn"),
                "handoff": handoff,
                "peering": bool(handoff and handoff.get("confirmed")),
            }
        )

    dest_asn = (run.get("meta") or {}).get("dest_asn")
    reached_as = None
    if dest_asn:
        reached_as = any(
            hop["asn"] == str(dest_asn) and hop["id"] != run.get("vantage")
            for hop in hops
            if hop.get("asn")
        )

    return {
        "run": {
            "run_id": run.get("run_id"),
            "target": target,
            "vantage": run.get("vantage"),
            "tool": run.get("tool"),
            "started_at": run.get("started_at"),
            "meta": run.get("meta") or {},
            "dest_asn": str(dest_asn) if dest_asn else None,
            "reached_as": reached_as,
        },
        "ping": run.get("meta", {}).get("ping"),
        "reachability": analysis.reachability(raw, target),
        "hops": hops,
        "edges": out_edges,
        "raw": raw,
        "target_fetches": fetch_by_ip.get(target, []),
    }


def _path_summary(graphs: list[dict], target: str | None) -> dict:
    """Aggregate the per-tool graphs into one cross-tool path overview.

    Countries are the first-appearance traversal order across tools. AS path is
    the most common tool AS sequence (the consensus), falling back to
    first-appearance order when every tool disagrees.
    """
    seqs: dict[str, tuple[str, ...]] = {}
    country_order: list[str] = []
    asn_order: list[str] = []
    name_by_asn: dict[str, str] = {}
    reached = 0
    for graph in graphs:
        tool = graph["run"]["tool"]
        if graph.get("reachability", {}).get("reached"):
            reached += 1
        hops = sorted(
            graph["hops"],
            key=lambda h: (h.get("ttl") if h.get("ttl") is not None else 0, h.get("id")),
        )
        seq: list[str] = []
        country_seq: list[str] = []
        for hop in hops:
            asn = hop.get("asn")
            if asn is not None:
                asn = str(asn)
                if hop.get("as_name") and asn not in name_by_asn:
                    name_by_asn[asn] = hop["as_name"]
                if not seq or seq[-1] != asn:
                    seq.append(asn)
                if asn not in asn_order:
                    asn_order.append(asn)
            country = hop.get("country")
            if country and (not country_seq or country_seq[-1] != country):
                country_seq.append(country)
        for country in country_seq:
            if country not in country_order:
                country_order.append(country)
        seqs[tool] = tuple(seq)

    counts: dict[tuple[str, ...], int] = {}
    for seq in seqs.values():
        if seq:
            counts[seq] = counts.get(seq, 0) + 1
    top_seq = max(counts, key=lambda seq: (counts[seq], len(seq)), default=None)
    asn_list = list(top_seq) if top_seq else asn_order
    return {
        "target": target,
        "tools": len(graphs),
        "reached": reached,
        "as_path": [{"asn": asn, "name": name_by_asn.get(asn)} for asn in asn_list],
        "countries": country_order,
        "agree": counts.get(top_seq, 0) if top_seq else 0,
        "total_paths": len(seqs),
    }


def build_graphs(conn, run_ids: list[str], dest: dict | None = None) -> dict:
    graphs = []
    target = None
    for run_id in run_ids:
        data = build(conn, run_id)
        run = data["run"]
        target = target or run.get("target")
        graphs.append(
            {
                **data,
                "label": f"{run.get('tool') or '?'} · {run.get('target') or '?'}",
            }
        )
    return {
        "target": target,
        "dest": dest,
        "graphs": graphs,
        "path_overview": _path_summary(graphs, target),
    }


def _embed(data: dict) -> str:
    text = json.dumps(data, ensure_ascii=False, sort_keys=True)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_html(conn, run_ids, dest: dict | None = None) -> str:
    if isinstance(run_ids, str):
        run_ids = [run_ids]
    template = TEMPLATE.read_text()
    return template.replace("/*__PATHS_DATA__*/", _embed(build_graphs(conn, list(run_ids), dest=dest)))
