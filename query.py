"""Reusable source-query helpers (source analysis layer).

Generic, path-agnostic: given an adapter id or an IP/ASN, fetch through aranya's
adapter registry and return parsed data. `paths/` (and anything else) builds on
these instead of talking to the network itself.
"""

from __future__ import annotations

import json

import cache
import observe
import sources


def _adapter(adapter_id: str) -> dict:
    for adapter in sources.SOURCES:
        if adapter["id"] == adapter_id:
            return adapter
    raise KeyError(adapter_id)


def fetch_parsed(adapter_id: str, ip: str = "", context: dict | None = None, refresh: bool = False) -> dict:
    key = cache.make("query", adapter_id, ip, json.dumps(context or {}, sort_keys=True))
    if not refresh:
        hit = cache.get(key)
        if hit is not None:
            return hit
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
    cache.put(key, parsed)
    return parsed


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


def as_name(asn) -> str | None:
    for adapter_id, field in (("peeringdb.net", "name"), ("ripestat.as-overview", "holder")):
        try:
            parsed = fetch_parsed(adapter_id, context={"asn": asn})
        except Exception:
            continue
        if parsed.get(field):
            return parsed[field]
    return None


def _geo_from(adapter_id: str, parsed: dict) -> dict | None:
    if adapter_id in ("maxmind.geolite2", "dbip.lite"):
        loc = {"city": parsed.get("city"), "country": parsed.get("country"),
               "latitude": parsed.get("latitude"), "longitude": parsed.get("longitude")}
    elif adapter_id == "ipwho.is":
        loc = {"city": parsed.get("city"), "country": parsed.get("country"),
               "latitude": parsed.get("latitude"), "longitude": parsed.get("longitude")}
    elif adapter_id == "ipinfo":
        loc = {"city": parsed.get("city"), "country": parsed.get("country"),
               "latitude": parsed.get("latitude"), "longitude": parsed.get("longitude")}
    elif adapter_id == "ripestat.geoloc":
        locations = parsed.get("locations") or []
        if not locations:
            return None
        best = max(locations, key=lambda item: item.get("covered_percentage") or 0)
        loc = {"city": best.get("city"), "country": best.get("country"),
               "latitude": best.get("latitude"), "longitude": best.get("longitude")}
    else:
        return None
    if not (loc["city"] or loc["country"] or loc["latitude"] is not None):
        return None
    return {**loc, "source": adapter_id}


def geo(ip: str) -> dict | None:
    for adapter_id in ("maxmind.geolite2", "dbip.lite", "ipwho.is", "ripestat.geoloc"):
        try:
            parsed = fetch_parsed(adapter_id, ip)
        except Exception:
            continue
        loc = _geo_from(adapter_id, parsed)
        if loc:
            return loc
    return None


def atlas_probes(asn) -> dict | None:
    try:
        return fetch_parsed("atlas.probes", context={"asn": asn})
    except Exception:
        return None


def peeringdb_net(asn):
    return fetch_parsed("peeringdb.net", context={"asn": asn}).get("net_id")


def facilities(net_id) -> list[dict]:
    return fetch_parsed("peeringdb.netfac", context={"net_id": net_id}).get("facilities") or []


def ixps(net_id) -> list[dict]:
    return fetch_parsed("peeringdb.netixlan", context={"net_id": net_id}).get("ix") or []
