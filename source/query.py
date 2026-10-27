"""Reusable source-query helpers (source-analysis layer).

Generic and path-agnostic: fetch through aranya's adapter registry and return
parsed data. `paths/` builds on these instead of talking to the network itself.
"""

from __future__ import annotations

import json
import time

from registry import observe, sources, store

from source import cache


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
    store.record_fetch(adapter_id, sources.redact_url(url), status, body, error, ip=ip or None)
    if error:
        raise RuntimeError(f"{adapter_id}: {error}")
    if adapter.get("delay"):
        time.sleep(adapter["delay"])
    parsed, _ = observe.observe(adapter, ip, body)
    cache.put(key, parsed)
    return parsed


def bgp_tools(ip: str) -> dict:
    """Parsed bgp.tools whois record for an IP (origin ASN, prefix, country)."""
    return fetch_parsed("bgp.tools", ip)


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
    try:
        parsed = bgp_tools(ip)
        if parsed.get("asn"):
            return {
                "asn": parsed["asn"],
                "prefix": parsed.get("prefix"),
                "country": parsed.get("country"),
                "source": "bgp.tools",
            }
    except Exception:
        pass
    return None


def geo(ip: str) -> dict | None:
    """Best-effort IP geolocation (city/coords/country) from a free source."""
    for adapter_id in ("ipwho.is", "ip.guide"):
        try:
            parsed = fetch_parsed(adapter_id, ip)
        except Exception:
            continue
        if parsed.get("latitude") is not None or parsed.get("country"):
            return parsed
    return None


def hostname(ip: str) -> str | None:
    """Best-effort reverse DNS / hostname for an IP."""
    try:
        parsed = fetch_parsed("rdns.ptr", ip)
        if parsed.get("hostname"):
            return parsed["hostname"]
    except Exception:
        pass
    try:
        parsed = fetch_parsed("internetdb", ip)
        hostnames = parsed.get("hostnames") or []
        if hostnames:
            return hostnames[0]
    except Exception:
        pass
    return None


def country_of(ip: str) -> str | None:
    """Country code for an IP, preferring origin-AS country then IP geolocation."""
    try:
        info = asn_of(ip)
        if info and info.get("country"):
            return info["country"]
    except Exception:
        pass
    geo_info = geo(ip)
    return (geo_info or {}).get("country")


def as_name(asn) -> str | None:
    for adapter_id, field in (("peeringdb.net", "name"), ("ripestat.as-overview", "holder")):
        try:
            parsed = fetch_parsed(adapter_id, context={"asn": asn})
        except Exception:
            continue
        if parsed.get(field):
            return parsed[field]
    return None


def peeringdb_net(asn):
    return fetch_parsed("peeringdb.net", context={"asn": asn}).get("net_id")


def facilities(net_id) -> list[dict]:
    return fetch_parsed("peeringdb.netfac", context={"net_id": net_id}).get("facilities") or []


def ixps(net_id) -> list[dict]:
    return fetch_parsed("peeringdb.netixlan", context={"net_id": net_id}).get("ix") or []


def ix_prefixes(ixlan_ids) -> list[dict]:
    """PeeringDB IX prefixes for a set of ixlan ids (prefix + ixlan_id)."""
    if not ixlan_ids:
        return []
    return fetch_parsed("peeringdb.ixpfx", context={"ixlan_ids": list(ixlan_ids)}).get("prefixes") or []
