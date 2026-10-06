"""Parsers for non-RIPE sources.

Each parser decodes a raw body into a lightly normalized dict. Bad JSON raises
json.JSONDecodeError so the caller can label a per-source parse error; non-object
payloads degrade to empty results rather than crashing.
"""

from __future__ import annotations

import json


def _obj(body: str) -> dict:
    payload = json.loads(body)
    return payload if isinstance(payload, dict) else {}


def _list(body: str) -> list:
    payload = json.loads(body)
    return payload if isinstance(payload, list) else []


def rdns(body: str) -> dict:
    return {"hostname": body or None}


def cymru(body: str) -> dict:
    payload = _obj(body)
    answers = payload.get("Answer") or []
    records: list[dict] = []
    for answer in answers:
        if not isinstance(answer, dict) or answer.get("type") != 16:
            continue
        data = (answer.get("data") or "").strip('"')
        parts = [part.strip() for part in data.split("|")]
        if len(parts) >= 3:
            records.append({"asn": parts[0], "prefix": parts[1], "country": parts[2]})
    return {"records": records}


def rdap(body: str) -> dict:
    payload = _obj(body)
    start = payload.get("startAddress")
    end = payload.get("endAddress")
    return {
        "handle": payload.get("handle"),
        "name": payload.get("name"),
        "start_address": start,
        "end_address": end,
        "range": f"{start}-{end}" if start and end else None,
        "country": payload.get("country"),
        "status": payload.get("status"),
        "type": payload.get("type"),
    }


def internetdb(body: str) -> dict:
    payload = _obj(body)
    return {
        "ip": payload.get("ip"),
        "hostnames": payload.get("hostnames") or [],
        "ports": payload.get("ports") or [],
        "cpes": payload.get("cpes") or [],
        "tags": payload.get("tags") or [],
        "vulns": payload.get("vulns") or [],
    }


def globalping(body: str) -> dict:
    payload = _obj(body)
    results: list[dict] = []
    for item in payload.get("results") or []:
        if not isinstance(item, dict):
            continue
        probe = item.get("probe") or {}
        stats = (item.get("result") or {}).get("stats") or {}
        results.append(
            {
                "country": probe.get("country"),
                "city": probe.get("city"),
                "latitude": probe.get("latitude"),
                "longitude": probe.get("longitude"),
                "asn": probe.get("asn"),
                "network": probe.get("network"),
                "min_rtt": stats.get("min"),
                "max_rtt": stats.get("max"),
                "avg_rtt": stats.get("avg"),
                "loss": stats.get("loss"),
            }
        )
    return {"results": results}


def peeringdb_net(body: str) -> dict:
    payload = _obj(body)
    data = payload.get("data") or []
    first = data[0] if isinstance(data, list) and data else {}
    return {
        "net_id": first.get("id"),
        "name": first.get("name"),
        "asn": first.get("asn"),
        "website": first.get("website"),
        "info_type": first.get("info_type"),
        "info_scope": first.get("info_scope"),
        "ix_count": first.get("ix_count"),
        "fac_count": first.get("fac_count"),
    }


def peeringdb_netfac(body: str) -> dict:
    payload = _obj(body)
    data = payload.get("data") or []
    facilities = [
        {"name": item.get("name"), "city": item.get("city"), "country": item.get("country")}
        for item in data
        if isinstance(item, dict)
    ]
    return {"facilities": facilities}


def peeringdb_netixlan(body: str) -> dict:
    payload = _obj(body)
    data = payload.get("data") or []
    ix = [
        {
            "name": item.get("name"),
            "ix_id": item.get("ix_id"),
            "ipaddr4": item.get("ipaddr4"),
            "ipaddr6": item.get("ipaddr6"),
        }
        for item in data
        if isinstance(item, dict)
    ]
    return {"ix": ix}


def crtsh(body: str) -> dict:
    payload = _list(body)
    certificates = [
        {"common_name": item.get("common_name"), "name_value": item.get("name_value")}
        for item in payload[:50]
        if isinstance(item, dict)
    ]
    return {"certificates": certificates}
