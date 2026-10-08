"""Render a run as a scan-centric, self-contained HTML graph.

Visual edges are packet traversal only: the measured hop-to-hop chain (including
ECMP branches and gap edges). Cross-layer facts are shown by **containment**, not
by crossing edges: hops are grouped into AS boxes and aliased hops are bracketed
as a machine.

Inter-AS edges carry a *suspected handoff* computed with no extra queries: the
intersection of the two ASes' already-fetched PeeringDB IXP/facility sets (the
likely interconnect). Hops are matched against their AS's `netixlan` peering-LAN
IPs to flag IXP presence directly. AS boxes list only the relevant (shared)
IXPs/facilities plus totals; the full lists and BGP sessions stay in the panel.
"""

from __future__ import annotations

import json
from pathlib import Path

import paths.analysis as analysis

TEMPLATE = Path(__file__).parent / "template.html"

W = 150
H = 30
COL_GAP = 220
ROW_GAP = 70
ORIGIN_X = 140
ORIGIN_Y = 140


def _load(conn, run_id: str) -> tuple[dict, dict[str, dict], list[dict]]:
    run = conn.execute(
        "SELECT run_id, target, src_ip, tool, started_at FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    run = (
        {"run_id": run[0], "target": run[1], "vantage": run[2], "tool": run[3], "started_at": run[4]}
        if run
        else {"run_id": run_id}
    )
    nodes: dict[str, dict] = {}
    for _node_id, layer, key, attrs in conn.execute("SELECT node_id, layer, key, attrs FROM nodes"):
        nodes[key] = {"id": key, "layer": layer, "key": key, "attrs": json.loads(attrs or "{}")}
    edges: list[dict] = []
    for layer, src, dst, ttl, count, min_rtt, attrs in conn.execute(
        "SELECT layer, src, dst, ttl, count, min_rtt_ms, attrs FROM edges WHERE run_id = ? "
        "ORDER BY layer, src, dst",
        (run_id,),
    ):
        data = json.loads(attrs or "{}")
        edges.append(
            {
                "source": src,
                "target": dst,
                "layer": layer,
                "ttl": ttl,
                "count": count,
                "min_rtt_ms": min_rtt,
                "attrs": data,
                "source_url": data.get("source_url"),
            }
        )
    return run, nodes, edges


def _hop_ttl(conn, run_id: str) -> dict[str, int]:
    rows = conn.execute(
        "SELECT src_ip, MIN(ttl) FROM hops WHERE run_id = ? AND src_ip IS NOT NULL GROUP BY src_ip",
        (run_id,),
    ).fetchall()
    return {ip: ttl for ip, ttl in rows}


def _raw_hops(conn, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT flow_id, ttl, src_ip, reply_ttl, rtt_ms FROM hops WHERE run_id = ? AND src_ip IS NOT NULL",
        (run_id,),
    ).fetchall()
    return [
        {"flow_id": flow, "ttl": ttl, "src_ip": ip, "reply_ttl": reply, "rtt_ms": rtt}
        for flow, ttl, ip, reply, rtt in rows
    ]


def _layer_map(nodes: dict[str, dict], layer: str) -> dict[str, dict]:
    return {key: node["attrs"] for key, node in nodes.items() if node["layer"] == layer}


def _collectors(edges: list[dict], nodes: dict[str, dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for edge in edges:
        if edge["layer"] != "session":
            continue
        name = edge["attrs"].get("collector")
        if not name:
            continue
        entry = out.setdefault(
            name,
            {"collector": name, "prefix": edge["attrs"].get("prefix"), "as_paths": [],
             "peers": [], "source_url": edge["source_url"], "geo": None},
        )
        path = edge["attrs"].get("as_path")
        if path and path not in entry["as_paths"]:
            entry["as_paths"].append(path)
        if edge["source"] and edge["source"] not in entry["peers"]:
            entry["peers"].append(edge["source"])
    for name, entry in out.items():
        attrs = nodes.get(f"COL:{name}", {}).get("attrs", {})
        if attrs.get("lat") is not None:
            entry["geo"] = {"latitude": attrs.get("lat"), "longitude": attrs.get("lng"), "country": attrs.get("country")}
    return out


def build(conn, run_id: str) -> dict:
    run, nodes, edges = _load(conn, run_id)
    target = run.get("target")
    ttl = _hop_ttl(conn, run_id)

    traversal = [edge for edge in edges if edge["layer"] == "interface"]
    trace: set[str] = set()
    for edge in traversal:
        trace.add(edge["source"])
        trace.add(edge["target"])
    if target:
        trace.add(target)

    as_of = {e["source"]: e["target"] for e in edges if e["layer"] == "origin" and e["source"] in trace}
    machine_of = {e["source"]: e["target"] for e in edges if e["layer"] == "machine" and e["source"] in trace}
    aliased = {
        ip: nodes[ip]["attrs"]["aliased_asns"]
        for ip in trace
        if nodes.get(ip, {}).get("attrs", {}).get("aliased_asns")
    }

    trust = analysis.ttl_trust(_raw_hops(conn, run_id))
    geo_of = {ip: nodes.get(ip, {}).get("attrs", {}).get("geo") for ip in trace}
    gap_before = {edge["target"] for edge in traversal if edge["attrs"].get("gap")}
    rtt_of = {ip: (trust.get(ip) or {}).get("rtt_ms") for ip in trace}
    measured = [ip for ip in trace if rtt_of.get(ip) is not None]
    long_haul = max(measured, key=lambda ip: rtt_of[ip]) if measured else None

    ix_nodes = _layer_map(nodes, "ix")
    fac_nodes = _layer_map(nodes, "facility")
    collectors = _collectors(edges, nodes)

    as_ix: dict[str, dict[str, dict]] = {}
    as_fac: dict[str, dict[str, dict]] = {}
    for edge in edges:
        if edge["layer"] == "ix":
            info = ix_nodes.get(edge["target"], {})
            as_ix.setdefault(edge["source"], {})[edge["target"]] = {
                "id": info.get("ix_id"),
                "name": info.get("name") or edge["target"],
                "ipaddr4": edge["attrs"].get("ipaddr4"),
                "ipaddr6": edge["attrs"].get("ipaddr6"),
                "source_url": info.get("source_url"),
            }
        elif edge["layer"] == "facility":
            info = fac_nodes.get(edge["target"], {})
            as_fac.setdefault(edge["source"], {})[edge["target"]] = {
                "name": info.get("name") or edge["target"],
                "city": info.get("city"),
                "country": info.get("country"),
                "latitude": info.get("latitude"),
                "longitude": info.get("longitude"),
                "source_url": info.get("source_url"),
            }

    ix_port: dict[tuple[str, str], str] = {}
    for asn, members in as_ix.items():
        for key, info in members.items():
            for field in ("ipaddr4", "ipaddr6"):
                if info.get(field):
                    ix_port[(asn, info[field])] = key

    columns: dict[int, list[str]] = {}
    for ip in trace:
        columns.setdefault(ttl.get(ip, 0), []).append(ip)
    order = sorted(columns)
    index = {value: position for position, value in enumerate(order)}
    tallest = max(len(members) for members in columns.values())
    position: dict[str, tuple[float, float]] = {}
    for value, members in columns.items():
        members.sort()
        offset = (tallest - len(members)) * ROW_GAP / 2
        for row, ip in enumerate(members):
            position[ip] = (ORIGIN_X + index[value] * COL_GAP, ORIGIN_Y + offset + row * ROW_GAP)

    relevant_ix: dict[str, set[str]] = {}
    relevant_fac: dict[str, set[str]] = {}
    out_edges = []
    for edge in traversal:
        if edge["source"] not in position or edge["target"] not in position:
            continue
        a_as, b_as = as_of.get(edge["source"]), as_of.get(edge["target"])
        geo_a, geo_b = geo_of.get(edge["source"]), geo_of.get(edge["target"])
        handoff = {"ixps": [], "facilities": [], "bgp": [], "geo": None}
        if a_as and b_as and a_as != b_as:
            shared_ix = set(as_ix.get(a_as, {})) & set(as_ix.get(b_as, {}))
            suspects: dict[str, dict] = {
                key: {**as_fac[a_as][key], "method": "shared"}
                for key in set(as_fac.get(a_as, {})) & set(as_fac.get(b_as, {}))
            }
            geo_match, distance = (False, None)
            if geo_a and geo_b:
                geo_match, distance = analysis.same_place(geo_a, geo_b)
            place = geo_a or geo_b
            if geo_match and place:
                for asn in (a_as, b_as):
                    for key, fac in as_fac.get(asn, {}).items():
                        if analysis.facility_matches_place(fac, place):
                            if key in suspects:
                                suspects[key]["method"] = "shared+geo"
                            else:
                                suspects[key] = {**fac, "method": "geo"}
            bgp_here = []
            for name, col in collectors.items():
                near = False
                if place and col["geo"]:
                    gap = analysis.haversine_km(place, col["geo"])
                    near = gap is not None and gap <= 500
                path_hits = any(
                    a_as[2:] in path.split() and b_as[2:] in path.split()
                    for path in col["as_paths"]
                )
                if near or path_hits:
                    bgp_here.append(
                        {"collector": name, "near": near, "path_hits": path_hits,
                         "as_paths": col["as_paths"][:3], "geo": col["geo"], "source_url": col["source_url"]}
                    )
            for key, fac in suspects.items():
                supports: set[str] = set()
                if fac["method"].startswith("shared"):
                    supports.add("shared")
                if "geo" in fac["method"]:
                    supports.add("geo")
                fac_geo = {"latitude": fac.get("latitude"), "longitude": fac.get("longitude")}
                fac_country = (fac.get("country") or "").strip().casefold()
                evidence = []
                for name, col in collectors.items():
                    if not col["geo"]:
                        continue
                    gap = analysis.haversine_km(fac_geo, col["geo"])
                    if gap is not None and gap <= 100:
                        supports.add("bgp")
                        evidence.append(
                            {"collector": name, "distance_km": round(gap),
                             "as_paths": col["as_paths"][:2], "source_url": col["source_url"]}
                        )
                    elif fac_country and fac_country == (col["geo"].get("country") or "").strip().casefold():
                        supports.add("bgp-country")
                fac["supports"] = sorted(supports)
                fac["bgp"] = evidence
                fac["weak"] = not ({"shared", "bgp", "bgp-country"} & supports)
            handoff = {
                "ixps": [as_ix[a_as][k] for k in sorted(shared_ix, key=lambda k: as_ix[a_as][k]["name"] or "")],
                "facilities": [suspects[k] for k in sorted(suspects, key=lambda k: suspects[k]["name"] or "")],
                "bgp": bgp_here,
                "geo": {
                    "a": analysis.place_of(geo_a),
                    "b": analysis.place_of(geo_b),
                    "match": geo_match,
                    "distance_km": distance,
                    "rtt_km_upper": analysis.rtt_km_upper(edge["min_rtt_ms"]),
                    "plausible": analysis.geo_plausible(distance, edge["min_rtt_ms"]),
                } if (geo_a or geo_b) else None,
            }
            if shared_ix:
                relevant_ix.setdefault(a_as, set()).update(shared_ix)
                relevant_ix.setdefault(b_as, set()).update(shared_ix)
            if suspects:
                relevant_fac.setdefault(a_as, set()).update(suspects)
                relevant_fac.setdefault(b_as, set()).update(suspects)
        out_edges.append(
            {
                "source": edge["source"],
                "target": edge["target"],
                "gap": bool(edge["attrs"].get("gap")),
                "count": edge["count"],
                "min_rtt_ms": edge["min_rtt_ms"],
                "ttl": edge["ttl"],
                "protocols": edge["attrs"].get("protocols") or [],
                "tools": edge["attrs"].get("tools") or [],
                "from_as": a_as,
                "to_as": b_as,
                "handoff": handoff,
            }
        )

    hops = []
    for ip in sorted(trace):
        x, y = position[ip]
        asn = as_of.get(ip)
        attrs = nodes.get(ip, {}).get("attrs", {})
        port = ix_port.get((asn, ip)) if asn else None
        if port and asn:
            relevant_ix.setdefault(asn, set()).add(port)
        hop_ix = as_ix.get(asn, {}).get(port) if port else None
        rel_ix = [
            as_ix[asn][k]
            for k in sorted(relevant_ix.get(asn, set()), key=lambda k: as_ix[asn][k]["name"] or "")
            if k in as_ix.get(asn, {})
        ] if asn else []
        rel_fac = [
            as_fac[asn][k]
            for k in sorted(relevant_fac.get(asn, set()), key=lambda k: as_fac.get(asn, {}).get(k, {}).get("name") or "")
            if k in as_fac.get(asn, {})
        ] if asn else []
        entry = trust.get(ip)
        confidence, reasons = analysis.ttl_confidence(entry, ip in gap_before)
        hops.append(
            {
                "id": ip,
                "ttl": ttl.get(ip),
                "x": x,
                "y": y,
                "as": asn,
                "as_name": nodes.get(asn, {}).get("attrs", {}).get("name"),
                "machine": machine_of.get(ip),
                "aliased_asns": aliased.get(ip),
                "is_target": ip == target,
                "ix": hop_ix,
                "relevant_ixps": rel_ix,
                "relevant_facilities": rel_fac,
                "total_ixps": len(as_ix.get(asn, {})),
                "total_facilities": len(as_fac.get(asn, {})),
                "geo": attrs.get("geo"),
                "rtt_ms": rtt_of.get(ip),
                "rtt_km_upper": analysis.rtt_km_upper(rtt_of.get(ip)),
                "long_haul": ip == long_haul,
                "ttl_flows": entry["flows"] if entry else None,
                "ttl_reply": entry["reply_ttl"] if entry else None,
                "ttl_return_hops": entry["return_hops"] if entry else None,
                "ttl_confidence": confidence,
                "ttl_reasons": reasons,
                "protocols": attrs.get("protocols") or [],
                "tools": attrs.get("tools") or [],
                "attrs": attrs,
                "source_url": attrs.get("source_url") or f"https://stat.ripe.net/{ip}",
            }
        )

    def box(members: list[str], pad: float, header: float = 16) -> dict:
        xs = [position[ip][0] for ip in members if ip in position]
        ys = [position[ip][1] for ip in members if ip in position]
        return {
            "x": min(xs) - pad,
            "y": min(ys) - pad - header,
            "w": max(xs) - min(xs) + W + 2 * pad,
            "h": max(ys) - min(ys) + H + 2 * pad + header,
        }

    containers = []
    as_members: dict[str, list[str]] = {}
    for ip, asn in as_of.items():
        as_members.setdefault(asn, []).append(ip)
    for asn, members in sorted(as_members.items()):
        as_attrs = nodes.get(asn, {}).get("attrs", {})
        info = {
            "name": as_attrs.get("name"),
            "probe_count": as_attrs.get("probe_count"),
            "probe_countries": as_attrs.get("probe_countries") or {},
            "ixps": [
                as_ix[asn][k]
                for k in sorted(relevant_ix.get(asn, set()), key=lambda k: as_ix[asn][k]["name"] or "")
                if k in as_ix.get(asn, {})
            ],
            "facilities": [
                as_fac[asn][k]
                for k in sorted(relevant_fac.get(asn, set()), key=lambda k: as_fac.get(asn, {}).get(k, {}).get("name") or "")
                if k in as_fac.get(asn, {})
            ],
            "total_ixps": len(as_ix.get(asn, {})),
            "total_facilities": len(as_fac.get(asn, {})),
            "source_url": f"https://stat.ripe.net/{asn}",
        }
        header = 30 if (info["ixps"] or info["facilities"]) else 16
        containers.append({"id": f"as:{asn}", "kind": "as", "label": asn, **box(members, 12, header), "info": info})

    machine_members: dict[str, list[str]] = {}
    for ip, machine in machine_of.items():
        machine_members.setdefault(machine, []).append(ip)
    for machine, members in sorted(machine_members.items()):
        containers.append({"id": f"machine:{machine}", "kind": "machine", "label": "same machine", **box(members, 6), "info": {}})

    return {
        "run": run,
        "hops": hops,
        "containers": containers,
        "edges": out_edges,
        "sessions": _sessions(edges),
        "collectors": sorted(collectors.values(), key=lambda item: item["collector"]),
        "facilities": _node_list(nodes, edges, "facility"),
        "ixps": _node_list(nodes, edges, "ix"),
    }


def _sessions(edges: list[dict]) -> list[dict]:
    sessions = []
    for edge in edges:
        if edge["layer"] != "session":
            continue
        sessions.append(
            {
                "speaker": edge["source"],
                "collector": edge["attrs"].get("collector"),
                "as_path": edge["attrs"].get("as_path"),
                "prefix": edge["attrs"].get("prefix"),
                "timestamp": edge["attrs"].get("timestamp"),
                "source_url": edge["source_url"],
            }
        )
    sessions.sort(key=lambda item: (item.get("prefix") or "", item.get("speaker") or ""))
    return sessions


def _node_list(nodes: dict[str, dict], edges: list[dict], layer: str) -> list[dict]:
    items = {}
    for key, node in nodes.items():
        if node["layer"] == layer:
            items[key] = {"id": key, "name": node["attrs"].get("name") or key, "source_url": node["attrs"].get("source_url")}
    return sorted(items.values(), key=lambda item: item["id"])


def _embed(data: dict) -> str:
    text = json.dumps(data, ensure_ascii=False, sort_keys=True)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_html(conn, run_id: str) -> str:
    template = TEMPLATE.read_text()
    return template.replace("/*__PATHS_DATA__*/", _embed(build(conn, run_id)))
