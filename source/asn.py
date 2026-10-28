"""AS-level announcement analysis: every prefix an AS originates, and where.

Given an ASN this answers two questions, reusing the aranya source adapters:

- `announced_prefixes(asn)` — every prefix the AS originates, from RIPEstat
  `announced-prefixes` (with first/last-seen timelines) and RouteViews
  `/asn/{asn}`.
- `announcement_locations(asn, prefix)` — which route collectors / vantage
  points observed that prefix, and the PeeringDB facilities/IXPs where the AS
  peers. BGP carries no "facility" attribute, so "where it was advertised" is
  recovered from the observer: RouteViews collector names are IXPs, RIS RRCs
  have a location, and bgproutes.io vantage points carry `ixp_name`, `country`
  and `org_name`.
"""

from __future__ import annotations

import argparse
import ipaddress
import json

from registry import sources, store

from source import bgp, cache, query

RIPESTAT_ANNOUNCED = "https://stat.ripe.net/data/announced-prefixes/data.json"


def _announced_ripestat(asn) -> list[dict]:
    url = f"{RIPESTAT_ANNOUNCED}?resource=AS{asn}"
    key = cache.make("http", url)
    hit = cache.get(key)
    if hit is not None:
        body = hit
    else:
        status, body, error = sources.http_get(url)
        store.record_fetch("ripestat.announced-prefixes", sources.redact_url(url), status, body, error)
        if error:
            raise RuntimeError(error)
        cache.put(key, body)
    data = json.loads(body).get("data") or {}
    out: list[dict] = []
    for item in data.get("prefixes") or []:
        prefix = item.get("prefix")
        if not prefix:
            continue
        timelines = item.get("timelines") or []
        first = min((t.get("starttime") for t in timelines if t.get("starttime")), default=None)
        last = max((t.get("endtime") for t in timelines if t.get("endtime")), default=None)
        out.append({"prefix": prefix, "first_seen": first, "last_seen": last, "source": "RIPEstat"})
    return out


def announced_prefixes(asn) -> list[dict]:
    """Merged, deduplicated list of prefixes announced by `asn`."""
    prefixes: dict[str, dict] = {}
    try:
        for entry in _announced_ripestat(asn):
            prefixes.setdefault(entry["prefix"], entry)
    except Exception:
        pass
    try:
        for prefix in bgp.prefixes_for_asn(asn):
            prefixes.setdefault(prefix, {"prefix": prefix, "first_seen": None, "last_seen": None, "source": "RouteViews"})
    except Exception:
        pass
    return sorted(prefixes.values(), key=lambda item: item["prefix"])


def contains_prefix(asn, prefix: str) -> bool:
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False
    for entry in announced_prefixes(asn):
        try:
            announced = ipaddress.ip_network(entry["prefix"], strict=False)
        except ValueError:
            continue
        if network == announced or network.subnet_of(announced):
            return True
    return False


def _first_ip(prefix: str) -> str:
    network = ipaddress.ip_network(prefix)
    if network.num_addresses > 2:
        return str(network.network_address + 1)
    return str(network.network_address)


def announcement_locations(asn, prefix: str) -> dict:
    """Where a prefix announced by `asn` is observed, plus the AS's own footprint."""
    asn = str(asn)
    ip = _first_ip(prefix)
    observers: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(source, location, **extra):
        key = (source, location or "")
        if key in seen:
            return
        seen.add(key)
        observers.append({"source": source, "location": location, **extra})

    try:
        routeviews = query.fetch_parsed("routeviews.prefix", ip)
        for route in routeviews.get("routes") or []:
            if route.get("prefix") == prefix and str(route.get("origin_asn")) == asn:
                for collector in route.get("collectors") or []:
                    add("RouteViews", collector)
    except Exception:
        pass

    try:
        ris = query.fetch_parsed("ris.looking-glass", ip)
        for rrc in ris.get("rrcs") or []:
            for peer in rrc.get("peers") or []:
                path = (peer.get("as_path") or "").split()
                origin = peer.get("asn_origin") or (path[-1] if path else None)
                if peer.get("prefix") == prefix and str(origin) == asn:
                    add("RIPE RIS", f"{rrc.get('rrc')} {rrc.get('location') or ''}".strip())
    except Exception:
        pass

    try:
        bgproutes = query.fetch_parsed(
            "bgproutes.prefix",
            ip,
            context={"prefix": prefix, "sources": "ris,routeviews,bgproutes.io", "vp_limit": 30},
        )
        for route in bgproutes.get("routes") or []:
            path = (route.get("as_path") or "").split()
            if route.get("prefix") == prefix and path and path[-1] == asn:
                add(
                    "bgproutes.io",
                    route.get("ixp_name") or route.get("vp_label"),
                    country=route.get("vp_country"),
                    org=route.get("org_name"),
                )
    except Exception:
        pass

    facilities: list[dict] = []
    ixps: list[dict] = []
    try:
        net_id = query.peeringdb_net(asn)
        if net_id:
            facilities = [
                {"name": f.get("name"), "city": f.get("city"), "country": f.get("country")}
                for f in query.facilities(net_id)
                if f.get("name")
            ]
            ixps = [{"name": ix.get("name")} for ix in query.ixps(net_id) if ix.get("name")]
    except Exception:
        pass

    return {"observers": observers, "facilities": facilities, "ixps": ixps}


def run_as(argv: list[str] | None = None) -> int:
    sources.load_env()
    parser = argparse.ArgumentParser(prog="aranya as", description="announcements of an ASN across collectors")
    parser.add_argument("asn", help="autonomous system number")
    parser.add_argument("--prefix", help="show where one prefix is observed")
    parser.add_argument("--limit", type=int, default=100, help="max prefixes to list (default 100)")
    args = parser.parse_args(argv)

    prefixes = announced_prefixes(args.asn)
    if args.prefix:
        print(f"AS{args.asn} announces {len(prefixes)} prefixes")
        print(f"contains {args.prefix}: {contains_prefix(args.asn, args.prefix)}")
        locations = announcement_locations(args.asn, args.prefix)
        print("\nobserved by:")
        if not locations["observers"]:
            print("  (none)")
        for obs in locations["observers"]:
            bits = [obs["location"] or "?"]
            if obs.get("country"):
                bits.append(obs["country"])
            if obs.get("org"):
                bits.append(obs["org"])
            print(f"  {obs['source']:<14} {', '.join(bits)}")
        if locations["facilities"]:
            print(f"\nPeeringDB facilities ({len(locations['facilities'])}):")
            for f in locations["facilities"][:20]:
                print(f"  {f['name']}{', ' + f['city'] if f.get('city') else ''}{', ' + f['country'] if f.get('country') else ''}")
        if locations["ixps"]:
            print(f"\nPeeringDB IXPs ({len(locations['ixps'])}):")
            print("  " + ", ".join(ix["name"] for ix in locations["ixps"][:40]))
        return 0

    print(f"AS{args.asn} announces {len(prefixes)} prefixes")
    for entry in prefixes[: args.limit]:
        times = ""
        if entry.get("first_seen") and entry.get("last_seen"):
            times = f"  [first {entry['first_seen']} last {entry['last_seen']}]"
        print(f"  {entry['prefix']}{times}")
    if len(prefixes) > args.limit:
        print(f"  ... {len(prefixes) - args.limit} more")
    return 0
