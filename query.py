"""Reusable source-query helpers (source analysis layer).

Generic, path-agnostic: given an adapter id or an IP/ASN, fetch through aranya's
adapter registry and return parsed data. `paths/` (and anything else) builds on
these instead of talking to the network itself.
"""

from __future__ import annotations

import observe
import sources


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
    return fetch_parsed("peeringdb.net", context={"asn": asn}).get("net_id")


def facilities(net_id) -> list[dict]:
    return fetch_parsed("peeringdb.netfac", context={"net_id": net_id}).get("facilities") or []


def ixps(net_id) -> list[dict]:
    return fetch_parsed("peeringdb.netixlan", context={"net_id": net_id}).get("ix") or []
