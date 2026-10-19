"""Graph mutation from source analysis.

`paths/` no longer talks to sources directly: it calls the source-analysis layer
(`query.py`, `bgp.py`) and turns facts into nodes/edges. Each fact lands in its
own layer, so measured router topology is never rewritten.

Layers added here:
  origin     hop/announcing IP -> AS            (Cymru, RIPEstat, BGP)
  as         AS -> AS neighbour                 (RIPEstat asn-neighbours)
  facility   AS -> PeeringDB facility
  ix         AS -> PeeringDB IX
  session    announcing IP -> collector         (RouteViews: real BGP sessions)
  collector  collector node (interface IP + lat/lon)
IP aliasing (one IP used by more than one AS) is recorded as a node attribute.
"""

from __future__ import annotations

import ipaddress
import os
from collections import defaultdict

import bgp
import query

import paths.alias as alias
import paths.store as store


def _env_off(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "on", "yes")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def as_key(asn) -> str:
    return f"AS{asn}"


def collector_key(name: str) -> str:
    return f"COL:{name}"


def target_ip(graph) -> str | None:
    best, best_ttl = None, -1
    for _src, dst, data in graph.edges(data=True):
        if data.get("layer") in (None, "interface") and _is_ip(dst):
            ttl = data.get("ttl")
            if ttl is not None and ttl > best_ttl:
                best, best_ttl = dst, ttl
    if best:
        return best
    ips = [node for node in graph.nodes if _is_ip(node)]
    return ips[-1] if ips else None


def target_prefix(graph) -> str | None:
    ip = target_ip(graph)
    if not ip:
        return None
    try:
        routes = query.fetch_parsed("routeviews.prefix", ip)["routes"]
    except Exception:
        routes = []
    best, best_length = None, -1
    for route in routes:
        prefix = route.get("prefix") or ""
        if "/" in prefix:
            try:
                length = int(prefix.split("/")[1])
            except ValueError:
                continue
            if length > best_length:
                best, best_length = route, length
    if best:
        return best.get("prefix")
    info = query.asn_of(ip)
    return info.get("prefix") if info else None


def _add_origin(conn, run_id, graph, ip, asn, source, prefix=None):
    key = as_key(asn)
    graph.add_node(key, layer="as", asn=str(asn))
    graph.add_edge(ip, key, layer="origin", asn=str(asn))
    store.add_node(conn, "as", key, {"asn": str(asn)})
    store.add_edge(conn, run_id, "origin", ip, key, attrs={"source": source, "prefix": prefix, "source_url": f"https://stat.ripe.net/{ip}"})


def _set_node_attrs(conn, graph, layer: str, key: str, extra: dict) -> None:
    if key in graph:
        graph.nodes[key].update(extra)
    attrs = {
        k: (sorted(v) if isinstance(v, set) else v)
        for k, v in graph.nodes.get(key, {}).items()
        if k != "layer"
    }
    attrs.update(extra)
    store.add_node(conn, layer, key, attrs)


def expand_as_names(conn, run_id, graph, asns: set[str]) -> int:
    named = 0
    for asn in sorted(asns):
        name = query.as_name(asn)
        if not name:
            continue
        _set_node_attrs(conn, graph, "as", as_key(asn), {"name": name})
        named += 1
    return named


def expand_geo(conn, run_id, graph, budget: int = 20) -> int:
    located = 0
    interfaces = [
        node for node, data in graph.nodes(data=True) if data.get("layer", "interface") == "interface"
    ]
    for ip in interfaces[:budget]:
        result = query.geo_all(ip)
        geo = result.get("geo")
        if not geo:
            continue
        _set_node_attrs(conn, graph, "interface", ip, {"geo": geo, "geo_sources": result.get("sources") or {}})
        located += 1
    return located


def _city(value) -> str:
    return (value or "").strip().casefold()


def expand_facility_geo(conn, run_id, graph, budget: int = 12) -> int:
    cities = {
        _city(data["geo"].get("city"))
        for _node, data in graph.nodes(data=True)
        if data.get("layer", "interface") == "interface" and data.get("geo")
    }
    cities.discard("")
    memberships: dict[str, list[str]] = {}
    for src, dst, data in graph.edges(data=True):
        if data.get("layer") == "facility":
            memberships.setdefault(dst, []).append(src)
    shared = {key for key, sources in memberships.items() if len(set(sources)) >= 2}
    candidates = [
        key
        for key, data in graph.nodes(data=True)
        if data.get("layer") == "facility" and (key in shared or _city(data.get("city")) in cities)
    ]
    located = 0
    for key in candidates[:budget]:
        data = graph.nodes[key]
        fac_id = data.get("fac_id")
        if fac_id is None:
            continue
        info = query.facility_info(fac_id)
        if not info:
            continue
        _set_node_attrs(
            conn, graph, "facility", key,
            {
                "latitude": info.get("latitude"),
                "longitude": info.get("longitude"),
                "city": info.get("city") or data.get("city"),
                "country": info.get("country") or data.get("country"),
            },
        )
        located += 1
    return located


def expand_ix_prefixes(conn, run_id, graph, budget: int = 12) -> int:
    memberships: dict[str, list[str]] = {}
    for src, dst, data in graph.edges(data=True):
        if data.get("layer") == "ix":
            memberships.setdefault(dst, []).append(src)
    shared = [key for key, sources in memberships.items() if len(set(sources)) >= 2]
    fetched = 0
    for key in shared[:budget]:
        data = graph.nodes[key]
        ixlan_id = data.get("ixlan_id")
        if ixlan_id is None:
            continue
        prefixes = query.ix_prefixes(ixlan_id)
        if not prefixes:
            continue
        _set_node_attrs(conn, graph, "ix", key, {"prefixes": prefixes})
        fetched += 1
    return fetched


def expand_probes(conn, run_id, graph, asns: set[str]) -> int:
    counted = 0
    for asn in sorted(asns):
        parsed = query.atlas_probes(asn)
        if not parsed:
            continue
        _set_node_attrs(
            conn, graph, "as", as_key(asn),
            {"probe_count": parsed.get("count"), "probe_countries": parsed.get("countries") or {}},
        )
        counted += 1
    return counted


def expand_origins(conn, run_id, graph, budget: int) -> set[str]:
    asns: set[str] = set()
    interfaces = [
        node for node, data in graph.nodes(data=True) if data.get("layer", "interface") == "interface"
    ]
    for ip in interfaces[:budget]:
        info = query.asn_of(ip)
        if not info:
            continue
        _add_origin(conn, run_id, graph, ip, info["asn"], info.get("source"), info.get("prefix"))
        asns.add(str(info["asn"]))
    return asns


def expand_neighbours(conn, run_id, graph, asns: set[str], cap: int) -> int:
    added = 0
    for asn in sorted(asns):
        try:
            entries = query.neighbours(asn)[:cap]
        except Exception:
            continue
        for entry in entries:
            neighbour = str(entry.get("asn"))
            key = as_key(neighbour)
            graph.add_node(key, layer="as", asn=neighbour)
            graph.add_edge(as_key(asn), key, layer="as", rel=entry.get("type"))
            store.add_node(conn, "as", key, {"asn": neighbour})
            store.add_edge(conn, run_id, "as", as_key(asn), key, attrs={"rel": entry.get("type"), "power": entry.get("power"), "source_url": f"https://stat.ripe.net/AS{asn}"})
            added += 1
    return added


def expand_peeringdb(conn, run_id, graph, asns: set[str], cap: int = 200) -> tuple[int, int]:
    facilities_added = ix_added = 0
    for asn in sorted(asns):
        try:
            net_id = query.peeringdb_net(asn)
        except Exception:
            net_id = None
        if net_id is None:
            continue
        try:
            for facility in query.facilities(net_id)[:cap]:
                name = facility.get("name")
                if not name:
                    continue
                key = f"FAC:{name}"
                graph.add_node(key, layer="facility", name=name, city=facility.get("city"), country=facility.get("country"), fac_id=facility.get("fac_id"))
                graph.add_edge(as_key(asn), key, layer="facility")
                store.add_node(conn, "facility", key, {"name": name, "city": facility.get("city"), "country": facility.get("country"), "fac_id": facility.get("fac_id"), "source_url": f"https://www.peeringdb.com/search?q={name}"})
                store.add_edge(conn, run_id, "facility", as_key(asn), key, attrs={"source_url": f"https://www.peeringdb.com/search?q={name}"})
                facilities_added += 1
        except Exception:
            pass
        try:
            for ix in query.ixps(net_id)[:cap]:
                ix_id = ix.get("ix_id")
                if ix_id is None:
                    continue
                key = f"IX:{ix_id}"
                ixlan_id = ix.get("ixlan_id")
                graph.add_node(key, layer="ix", name=ix.get("name"))
                graph.add_edge(as_key(asn), key, layer="ix", ipaddr4=ix.get("ipaddr4"), ipaddr6=ix.get("ipaddr6"))
                store.add_node(conn, "ix", key, {"name": ix.get("name"), "ix_id": ix_id, "ixlan_id": ixlan_id, "source_url": f"https://www.peeringdb.com/ix/{ix_id}"})
                store.add_edge(conn, run_id, "ix", as_key(asn), key, attrs={"source_url": f"https://www.peeringdb.com/ix/{ix_id}", "ipaddr4": ix.get("ipaddr4"), "ipaddr6": ix.get("ipaddr6")})
                ix_added += 1
        except Exception:
            pass
    return facilities_added, ix_added


def expand_sessions(conn, run_id, graph, cap: int = 40) -> dict:
    prefix = target_prefix(graph)
    if not prefix:
        return {"prefix": None, "sessions": 0, "collectors": 0}
    try:
        routes = bgp.announcements(prefix)
    except Exception:
        return {"prefix": prefix, "sessions": 0, "collectors": 0}
    facts = bgp.sessions(routes, cap=cap)
    collectors: dict[str, dict] = {}
    sessions = 0
    for fact in facts:
        speaker = fact.get("speaker_ip")
        speaker_asn = fact.get("speaker_asn")
        name = fact.get("collector")
        if not speaker or not name:
            continue
        graph.add_node(speaker, layer="interface")
        store.add_node(conn, "interface", speaker)
        if speaker_asn is not None:
            _add_origin(conn, run_id, graph, speaker, speaker_asn, "routeviews")
        if name not in collectors:
            try:
                info = bgp.collector(name)
            except Exception:
                info = {}
            collectors[name] = info
            graph.add_node(collector_key(name), layer="collector", name=name)
            store.add_node(conn, "collector", collector_key(name), {"name": name, "source_url": f"https://api.routeviews.org/collector/?name={name}", **info})
        graph.add_edge(speaker, collector_key(name), layer="session", collector=name)
        store.add_edge(
            conn, run_id, "session", speaker, collector_key(name),
            attrs={"collector": name, "as_path": fact.get("as_path"), "prefix": prefix, "timestamp": fact.get("timestamp"), "source_url": f"https://api.routeviews.org/prefix/{prefix}"},
        )
        sessions += 1
    return {"prefix": prefix, "sessions": sessions, "collectors": len(collectors)}


def _cached_rdns(ip: str) -> str | None:
    try:
        return (query.fetch_parsed("rdns.ptr", ip) or {}).get("hostname")
    except Exception:
        return None


def expand_aliases(conn, run_id, graph, resolver=None) -> dict:
    resolver = resolver or _cached_rdns
    hops: set[str] = set()
    for src, dst, data in graph.edges(data=True):
        if data.get("layer") in (None, "interface"):
            hops.add(src)
            hops.add(dst)
    rdns = alias.rdns_map(sorted(hops), resolver)
    clusters = alias.clusters(alias.rdns_pairs(rdns))
    for members in clusters:
        key = alias.machine_key(members)
        graph.add_node(key, layer="machine", interfaces=members)
        store.add_node(conn, "machine", key, {"interfaces": members, "method": "rdns"})
        for ip in members:
            graph.add_edge(ip, key, layer="machine", method="rdns")
            store.add_edge(conn, run_id, "machine", ip, key, attrs={"method": "rdns", "confidence": 0.8})
    return {"machines": len(clusters), "clustered": sum(len(members) for members in clusters)}


def mark_aliasing(conn, run_id, graph) -> dict[str, list[str]]:
    asns: dict[str, set[str]] = defaultdict(set)
    for src, dst, data in graph.edges(data=True):
        if data.get("layer") == "origin":
            asns[src].add(dst)
    aliased = {ip: sorted(values) for ip, values in asns.items() if len(values) > 1}
    for ip, values in aliased.items():
        graph.nodes[ip]["aliased_asns"] = values
        store.add_node(conn, "interface", ip, {"aliased_asns": values})
    return aliased


def expand(
    conn,
    run_id,
    graph,
    budget: int = 20,
    neighbours_cap: int = 40,
    sessions: bool = True,
    peeringdb: bool = True,
    neighbours: bool = True,
    aliases: bool = True,
    geo: bool = True,
    probes: bool = True,
) -> dict:
    sessions = sessions and not _env_off("PATHS_NO_SESSIONS")
    peeringdb = peeringdb and not _env_off("PATHS_NO_PEERINGDB")
    neighbours = neighbours and not _env_off("PATHS_NO_NEIGHBOURS")
    aliases = aliases and not _env_off("PATHS_NO_ALIAS")
    geo = geo and not _env_off("PATHS_NO_GEO")
    probes = probes and not _env_off("PATHS_NO_PROBES")

    asns = expand_origins(conn, run_id, graph, budget)
    named = expand_as_names(conn, run_id, graph, asns)
    as_edges = expand_neighbours(conn, run_id, graph, asns, neighbours_cap) if neighbours else 0
    facilities_added, ix_added = expand_peeringdb(conn, run_id, graph, asns) if peeringdb else (0, 0)
    session_stats = expand_sessions(conn, run_id, graph) if sessions else {"prefix": None, "sessions": 0, "collectors": 0}
    alias_stats = expand_aliases(conn, run_id, graph) if aliases else {"machines": 0, "clustered": 0}
    located = expand_geo(conn, run_id, graph, budget) if geo else 0
    facility_geo = expand_facility_geo(conn, run_id, graph) if geo else 0
    ix_prefixes = expand_ix_prefixes(conn, run_id, graph) if peeringdb else 0
    probed = expand_probes(conn, run_id, graph, asns) if probes else 0
    aliased = mark_aliasing(conn, run_id, graph)
    store.commit(conn)
    return {
        "origin_edges": len(asns),
        "as_edges": as_edges,
        "facilities": facilities_added,
        "ixps": ix_added,
        "asns": sorted(asns),
        "named": named,
        "located": located,
        "facility_geo": facility_geo,
        "ix_prefixes": ix_prefixes,
        "probed": probed,
        "sessions": session_stats,
        "machines": alias_stats["machines"],
        "clustered": alias_stats["clustered"],
        "aliased": aliased,
    }
