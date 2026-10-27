"""Graph enrichment from the source-analysis layer.

Adds the facts the graph needs, without rewriting measured topology:

- every hop IP is resolved to its origin AS (`query.asn_of`), stored as node
  attrs `asn` / `as_name`;
- every AS's PeeringDB facilities and IXPs are fetched once (cached) and stored
  on an `as` node;
- every inter-AS traversal edge gets a `handoff`: the facilities and IXPs where
  both ASes are present, whether the outgoing AS advertises the destination IP
  (`bgp.owns`), plus peering evidence (adjacent AS paths from RouteViews, RIPE
  RIS and bgproutes.io vantage points) and whether the two hop IPs are
  geographically consistent. That is what the HTML shows on the link.
"""

from __future__ import annotations

import ipaddress

from source import bgp, query, topology

import paths.store as store


def as_key(asn) -> str:
    return f"AS{asn}"


def _facility_key(facility: dict):
    return facility.get("fac_id") or facility.get("name")


def _ix_key(ix: dict):
    return ix.get("ix_id")


def _geo(ip: str, asn_info: dict) -> dict:
    """Country + coordinates for an interface IP, best-effort and cached upstream."""
    country = (asn_info or {}).get("country")
    lat = lon = city = None
    located = None
    try:
        if ipaddress.ip_address(ip).is_global:
            located = query.geo(ip)
    except Exception:
        located = None
    if located:
        country = located.get("country") or country
        city = located.get("city")
        lat = located.get("latitude")
        lon = located.get("longitude")
    return {"country": country, "city": city, "latitude": lat, "longitude": lon}


def _geo_match(a: dict, b: dict) -> dict:
    same_country = bool(a["country"] and b["country"] and a["country"] == b["country"])
    distance = topology.distance_km(
        a.get("latitude"), a.get("longitude"), b.get("latitude"), b.get("longitude")
    )
    close = distance is not None and distance < 800
    return {
        "src_country": a["country"],
        "dst_country": b["country"],
        "same_country": same_country,
        "distance_km": round(distance, 1) if distance is not None else None,
        "match": same_country or close,
    }


def expand(conn, run_id, graph, target: str) -> dict:
    from registry import store as raw_store

    with raw_store.capture(conn):
        return _expand(conn, run_id, graph, target)


def _expand(conn, run_id, graph, target: str) -> dict:
    interfaces = [node for node in graph.nodes()]
    ip_info: dict[str, dict] = {}
    asns: set[str] = set()
    for ip in interfaces:
        info = query.asn_of(ip)
        ip_info[ip] = info or {}
        if not info or not info.get("asn"):
            continue
        asn = str(info["asn"])
        asns.add(asn)
        graph.nodes[ip]["asn"] = asn

    # Once per unique IP/AS: geography, hostname, neighbours, PeeringDB directory.
    geo_cache = {ip: _geo(ip, ip_info[ip]) for ip in interfaces}
    neighbours = {asn: topology.neighbour_map(asn) for asn in asns}

    as_name: dict[str, str | None] = {}
    as_fac: dict[str, dict] = {}
    as_ix: dict[str, dict] = {}
    ip_ixp: dict[str, dict] = {}
    ix_nets: list[tuple[object, str]] = []
    for asn in sorted(asns):
        name = query.as_name(asn)
        as_name[asn] = name
        try:
            net_id = query.peeringdb_net(asn)
        except Exception:
            net_id = None
        facilities = query.facilities(net_id) if net_id else []
        ixs = query.ixps(net_id) if net_id else []
        as_fac[asn] = {_facility_key(f): f for f in facilities if _facility_key(f)}
        as_ix[asn] = {_ix_key(ix): ix for ix in ixs if _ix_key(ix) is not None}
        for ix in ixs:
            for ip in (ix.get("ipaddr4"), ix.get("ipaddr6")):
                if ip:
                    ip_ixp[ip] = {"name": ix.get("name"), "ix_id": ix.get("ix_id")}
        ixlan_ids = sorted({ix.get("ixlan_id") for ix in ixs if ix.get("ixlan_id") is not None})
        if ixlan_ids and len(ixlan_ids) <= 200:
            name_by_ixlan = {ix.get("ixlan_id"): ix.get("name") for ix in ixs if ix.get("ixlan_id") is not None}
            try:
                prefixes = query.ix_prefixes(ixlan_ids)
            except Exception:
                prefixes = []
            for entry in prefixes:
                try:
                    net = ipaddress.ip_network(entry["prefix"])
                except Exception:
                    continue
                name = name_by_ixlan.get(entry["ixlan_id"])
                if name:
                    ix_nets.append((net, name))
        store.add_node(
            conn,
            "as",
            as_key(asn),
            {
                "asn": asn,
                "name": name,
                "facilities": [
                    {"name": f.get("name"), "city": f.get("city"), "country": f.get("country")}
                    for f in facilities
                    if f.get("name")
                ],
                "ixps": [{"name": ix.get("name"), "ix_id": ix.get("ix_id")} for ix in ixs if ix.get("name")],
            },
        )

    # Attach the resolved facts to each interface node so the HTML panel can
    # show them the way `aranya <IP>` shows a claim's provenance.
    for ip in interfaces:
        info = ip_info.get(ip) or {}
        asn = str(info["asn"]) if info.get("asn") is not None else None
        geo = geo_cache.get(ip) or {}
        hostname = None
        try:
            if ipaddress.ip_address(ip).is_global:
                hostname = query.hostname(ip)
        except Exception:
            hostname = None
        ixp = ip_ixp.get(ip)
        if not ixp:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                addr = None
            if addr is not None and addr.is_global:
                for net, name in ix_nets:
                    if addr in net:
                        ixp = {"name": name}
                        break
        bgp_info = {}
        try:
            if ipaddress.ip_address(ip).is_global:
                bgp_info = query.bgp_tools(ip) or {}
        except Exception:
            bgp_info = {}
        store.set_node_attrs(
            conn,
            "interface",
            ip,
            {
                "asn": asn,
                "as_name": as_name.get(asn) if asn else None,
                "prefix": info.get("prefix"),
                "country": geo.get("country"),
                "city": geo.get("city"),
                "latitude": geo.get("latitude"),
                "longitude": geo.get("longitude"),
                "hostname": hostname,
                "ixp": ixp["name"] if ixp else None,
                "bgp_asn": bgp_info.get("asn"),
                "bgp_prefix": bgp_info.get("prefix"),
                "bgp_country": bgp_info.get("country"),
                "bgp_name": bgp_info.get("name"),
            },
        )

    # AS paths toward the destination: the BGP view of every hop on this route.
    target_prefix = (ip_info.get(target) or {}).get("prefix")
    if not target_prefix:
        target_prefix = (query.asn_of(target) or {}).get("prefix")
    paths = topology.target_paths(target, prefix=target_prefix)

    handoffs = 0
    for src, dst in graph.edges():
        a_asn = graph.nodes[src].get("asn")
        b_asn = graph.nodes[dst].get("asn")
        if not (a_asn and b_asn) or a_asn == b_asn:
            continue

        adjacency = [
            entry for entry in paths if topology.contiguous(a_asn, b_asn, entry["as_path"])
        ]
        relation = neighbours.get(a_asn, {}).get(b_asn) or neighbours.get(b_asn, {}).get(a_asn)
        peering_neighbours = bool(relation)
        shared_fac = [
            {
                "name": as_fac[a_asn][k].get("name"),
                "city": as_fac[a_asn][k].get("city"),
                "country": as_fac[a_asn][k].get("country"),
            }
            for k in sorted(set(as_fac.get(a_asn, {})) & set(as_fac.get(b_asn, {})))
        ]
        shared_ix = [
            {"name": as_ix[a_asn][k].get("name")}
            for k in sorted(set(as_ix.get(a_asn, {})) & set(as_ix.get(b_asn, {})))
        ]
        geo = _geo_match(geo_cache[src], geo_cache[dst])
        try:
            announces = bgp.owns(int(a_asn), target)
        except Exception:
            announces = None
        confirmed = bool(adjacency) and geo["match"]
        handoff = {
            "from_as": a_asn,
            "to_as": b_asn,
            "facilities": shared_fac,
            "ixps": shared_ix,
            "ixp": {
                "src": ip_ixp.get(src, {}).get("name"),
                "dst": ip_ixp.get(dst, {}).get("name"),
            },
            "announces_dest": announces,
            "adjacency": adjacency,
            "neighbours": peering_neighbours,
            "ris": {
                "type": relation.get("type") if relation else None,
                "power": relation.get("power") if relation else None,
                "v4_peers": relation.get("v4_peers") if relation else None,
                "v6_peers": relation.get("v6_peers") if relation else None,
            },
            "geo": geo,
            "confirmed": confirmed,
        }
        graph[src][dst]["handoff"] = handoff
        store.set_edge_attrs(conn, run_id, "interface", src, dst, {"handoff": handoff})
        handoffs += 1

    store.commit(conn)
    return {
        "hops": len(interfaces),
        "asns": sorted(asns),
        "handoffs": handoffs,
    }
