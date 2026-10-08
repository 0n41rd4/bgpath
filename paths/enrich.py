"""Symbiotic enrichment: let source queries enlarge the topological graph.

Walking the interface layer yields hop IPs; each is an entry point to more
topology. An IP gives an origin AS (Cymru/RIPEstat); an AS gives its BGP
neighbours (RIPEstat asn-neighbours); an AS gives its facilities and IXPs
(PeeringDB). Every result adds nodes and edges to a *different* layer, so the
router topology is never overwritten by BGP, facility or geo claims.
"""

from __future__ import annotations

import observe
import sources

import paths.store as store


def _adapter(adapter_id: str) -> dict:
    for adapter in sources.SOURCES:
        if adapter["id"] == adapter_id:
            return adapter
    raise KeyError(adapter_id)


def fetch_parsed(adapter_id: str, ip: str = "", context: dict | None = None) -> dict:
    adapter = _adapter(adapter_id)
    ctx = {"ip": ip, **(context or {})}
    url = adapter["url"](ctx)
    if "fetch" in adapter:
        status, body, error = adapter["fetch"](ip, ctx)
    else:
        status, body, error = sources.http_get(url)
    if error:
        raise RuntimeError(f"{adapter_id}: {error}")
    parsed, _ = observe.observe(adapter, ip, body)
    return parsed


def as_key(asn) -> str:
    return f"AS{asn}"


def asn_of(ip: str) -> dict | None:
    try:
        parsed = fetch_parsed("cymru.origin", ip)
        records = parsed.get("records") or []
        if records and records[0].get("asn"):
            return {
                "asn": records[0]["asn"],
                "prefix": records[0].get("prefix"),
                "country": records[0].get("country"),
                "source": "cymru.origin",
            }
    except Exception:
        pass
    try:
        parsed = fetch_parsed("ripestat.network-info", ip)
        asns = parsed.get("asns") or []
        if asns:
            return {"asn": str(asns[0]), "prefix": parsed.get("prefix"), "source": "ripestat.network-info"}
    except Exception:
        pass
    return None


def neighbours(asn) -> list[dict]:
    parsed = fetch_parsed("ripestat.asn-neighbours", context={"asn": asn})
    return [entry for entry in parsed.get("neighbours") or [] if isinstance(entry, dict)]


def peeringdb_net(asn):
    parsed = fetch_parsed("peeringdb.net", context={"asn": asn})
    return parsed.get("net_id")


def facilities(net_id) -> list[dict]:
    parsed = fetch_parsed("peeringdb.netfac", context={"net_id": net_id})
    return parsed.get("facilities") or []


def ixps(net_id) -> list[dict]:
    parsed = fetch_parsed("peeringdb.netixlan", context={"net_id": net_id})
    return parsed.get("ix") or []


def expand(conn, run_id: str, graph, budget: int = 20, neighbours_cap: int = 40) -> dict:
    stats = {"interfaces": 0, "asns": set(), "origin_edges": 0, "as_edges": 0, "facilities": 0, "ixps": 0}
    interfaces = [
        node for node, data in graph.nodes(data=True) if data.get("layer", "interface") == "interface"
    ]
    for ip in interfaces[:budget]:
        info = asn_of(ip)
        if not info:
            continue
        key = as_key(info["asn"])
        graph.add_node(key, layer="as", asn=info["asn"])
        graph.add_edge(ip, key, layer="origin", asn=info["asn"])
        store.add_node(conn, "as", key, {"asn": info["asn"]})
        store.add_edge(
            conn, run_id, "origin", ip, key, attrs={"source": info.get("source"), "prefix": info.get("prefix")}
        )
        stats["interfaces"] += 1
        stats["asns"].add(str(info["asn"]))
        stats["origin_edges"] += 1

    for asn in sorted(stats["asns"]):
        try:
            for entry in neighbours(asn)[:neighbours_cap]:
                neighbour = str(entry.get("asn"))
                nkey = as_key(neighbour)
                graph.add_node(nkey, layer="as", asn=neighbour)
                graph.add_edge(as_key(asn), nkey, layer="as", rel=entry.get("type"))
                store.add_node(conn, "as", nkey, {"asn": neighbour})
                store.add_edge(
                    conn, run_id, "as", as_key(asn), nkey,
                    attrs={"rel": entry.get("type"), "power": entry.get("power")},
                )
                stats["as_edges"] += 1
        except Exception:
            pass

        try:
            net_id = peeringdb_net(asn)
        except Exception:
            net_id = None
        if net_id is None:
            continue

        try:
            for facility in facilities(net_id):
                name = facility.get("name")
                if not name:
                    continue
                fkey = f"FAC:{name}"
                graph.add_node(fkey, layer="facility", name=name)
                graph.add_edge(as_key(asn), fkey, layer="facility")
                store.add_node(
                    conn, "facility", fkey,
                    {"name": name, "city": facility.get("city"), "country": facility.get("country")},
                )
                store.add_edge(conn, run_id, "facility", as_key(asn), fkey)
                stats["facilities"] += 1
        except Exception:
            pass

        try:
            for ix in ixps(net_id):
                ix_id = ix.get("ix_id")
                if ix_id is None:
                    continue
                ikey = f"IX:{ix_id}"
                graph.add_node(ikey, layer="ix", name=ix.get("name"))
                graph.add_edge(as_key(asn), ikey, layer="ix")
                store.add_node(conn, "ix", ikey, {"name": ix.get("name"), "ix_id": ix_id})
                store.add_edge(conn, run_id, "ix", as_key(asn), ikey)
                stats["ixps"] += 1
        except Exception:
            pass

    store.commit(conn)
    stats["asns"] = sorted(stats["asns"])
    return stats
