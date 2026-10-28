"""Parsers for the RIPE-family APIs (RIPEstat data calls + RIPE IPmap).

Each parser decodes the body and returns a lightly normalized dict of the
fields aranya cares about. Bad JSON raises json.JSONDecodeError so the caller
can label it a per-source parse error; non-object payloads degrade to empty
results rather than crashing.
"""

from __future__ import annotations

import json


def _ripestat_data(body: str) -> dict:
    payload = json.loads(body)
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data")
    return data if isinstance(data, dict) else {}


def network_info(body: str) -> dict:
    data = _ripestat_data(body)
    asns = data.get("asns")
    return {
        "prefix": data.get("prefix"),
        "asns": asns if isinstance(asns, list) else [],
    }


def geoloc(body: str) -> dict:
    data = _ripestat_data(body)
    located = data.get("located_resources")
    locations: list[dict] = []
    if isinstance(located, list):
        for resource in located:
            if not isinstance(resource, dict):
                continue
            for loc in resource.get("locations") or []:
                if isinstance(loc, dict):
                    locations.append(
                        {
                            "resource": resource.get("resource"),
                            "country": loc.get("country"),
                            "city": loc.get("city"),
                            "latitude": loc.get("latitude"),
                            "longitude": loc.get("longitude"),
                            "covered_percentage": loc.get("covered_percentage"),
                        }
                    )
    return {"locations": locations}


def as_overview(body: str) -> dict:
    data = _ripestat_data(body)
    block = data.get("block")
    return {
        "asn": data.get("resource"),
        "holder": data.get("holder"),
        "announced": data.get("announced"),
        "block": block.get("resource") if isinstance(block, dict) else None,
    }


def asn_neighbours(body: str) -> dict:
    data = _ripestat_data(body)
    neighbours = data.get("neighbours")
    return {
        "asn": data.get("resource"),
        "neighbour_counts": data.get("neighbour_counts") or {},
        "neighbours": neighbours if isinstance(neighbours, list) else [],
    }


def announced_prefixes(body: str) -> dict:
    data = _ripestat_data(body)
    prefixes = [
        item.get("prefix")
        for item in data.get("prefixes") or []
        if isinstance(item, dict) and item.get("prefix")
    ]
    return {"prefixes": prefixes, "count": len(prefixes)}


def looking_glass(body: str) -> dict:
    data = _ripestat_data(body)
    rrcs: list[dict] = []
    for rrc in data.get("rrcs") or []:
        if not isinstance(rrc, dict):
            continue
        peers: list[dict] = []
        for peer in rrc.get("peers") or []:
            if not isinstance(peer, dict):
                continue
            peers.append(
                {
                    "peer": peer.get("peer"),
                    "asn_origin": peer.get("asn_origin"),
                    "as_path": peer.get("as_path"),
                    "prefix": peer.get("prefix"),
                    "next_hop": peer.get("next_hop"),
                    "last_updated": peer.get("last_updated"),
                    "community": peer.get("community"),
                }
            )
        rrcs.append(
            {
                "rrc": rrc.get("rrc"),
                "location": rrc.get("location"),
                "scope": rrc.get("scope"),
                "peers": peers,
            }
        )
    return {
        "query_time": data.get("query_time"),
        "latest_time": data.get("latest_time"),
        "rrcs": rrcs,
    }


def ipmap(body: str) -> dict:
    payload = json.loads(body)
    if not isinstance(payload, dict):
        return {"locations": []}
    locations: list[dict] = []
    for loc in payload.get("locations") or []:
        if isinstance(loc, dict):
            locations.append(
                {
                    "id": loc.get("id"),
                    "type": loc.get("type"),
                    "city": loc.get("cityName"),
                    "country": loc.get("countryName"),
                    "latitude": loc.get("latitude"),
                    "longitude": loc.get("longitude"),
                    "score": loc.get("score"),
                }
            )
    return {"locations": locations}
