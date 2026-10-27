"""Parsers for non-RIPE sources.

Each parser decodes a raw body into a lightly normalized dict. Bad JSON raises
json.JSONDecodeError so the caller can label a per-source parse error; non-object
payloads degrade to empty results rather than crashing.
"""

from __future__ import annotations

import json
import re


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
        {"name": item.get("name"), "city": item.get("city"), "country": item.get("country"), "fac_id": item.get("fac_id")}
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
            "ixlan_id": item.get("ixlan_id"),
            "ipaddr4": item.get("ipaddr4"),
            "ipaddr6": item.get("ipaddr6"),
        }
        for item in data
        if isinstance(item, dict)
    ]
    return {"ix": ix}


def peeringdb_fac(body: str) -> dict:
    payload = _obj(body)
    data = payload.get("data") or []
    facilities = [
        {
            "fac_id": item.get("id"),
            "name": item.get("name"),
            "city": item.get("city"),
            "country": item.get("country"),
            "latitude": item.get("latitude"),
            "longitude": item.get("longitude"),
        }
        for item in data
        if isinstance(item, dict)
    ]
    return {"facilities": facilities}


def peeringdb_ixpfx(body: str) -> dict:
    payload = _obj(body)
    data = payload.get("data") or []
    prefixes = [
        {"prefix": item.get("prefix"), "protocol": item.get("protocol"), "ixlan_id": item.get("ixlan_id")}
        for item in data
        if isinstance(item, dict)
    ]
    return {"prefixes": prefixes}


def crtsh(body: str) -> dict:
    payload = _list(body)
    certificates = [
        {"common_name": item.get("common_name"), "name_value": item.get("name_value")}
        for item in payload[:50]
        if isinstance(item, dict)
    ]
    return {"certificates": certificates}


def ipinfo(body: str) -> dict:
    payload = _obj(body)
    loc = (payload.get("loc") or "").split(",")
    asn = payload.get("asn")
    asn_value = asn.get("asn") if isinstance(asn, dict) else None
    return {
        "org": payload.get("org"),
        "hostname": payload.get("hostname"),
        "city": payload.get("city"),
        "region": payload.get("region"),
        "country": payload.get("country"),
        "latitude": _float(loc[0]) if len(loc) == 2 else None,
        "longitude": _float(loc[1]) if len(loc) == 2 else None,
        "asn": _asn_digits(asn_value) or _asn_digits(payload.get("org")),
        "anycast": payload.get("anycast"),
    }


def shodan(body: str) -> dict:
    payload = _obj(body)
    return {
        "org": payload.get("org"),
        "asn": payload.get("asn"),
        "hostnames": payload.get("hostnames") or [],
        "ports": payload.get("ports") or [],
        "os": payload.get("os"),
        "city": payload.get("city"),
        "country": payload.get("country_name"),
        "latitude": payload.get("latitude"),
        "longitude": payload.get("longitude"),
    }


def mmdb(body: str) -> dict:
    payload = _obj(body)
    country = payload.get("country") or {}
    city = payload.get("city") or {}
    location = payload.get("location") or {}
    subdivisions = payload.get("subdivisions") or []
    subdivision = subdivisions[0] if isinstance(subdivisions, list) and subdivisions else {}
    return {
        "country": country.get("iso_code"),
        "city": (city.get("names") or {}).get("en"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "subdivision": subdivision.get("iso_code"),
    }


def mmdb_asn(body: str) -> dict:
    payload = _obj(body)
    number = payload.get("autonomous_system_number")
    return {
        "asn": str(number) if number is not None else None,
        "org": payload.get("autonomous_system_organization"),
    }


def ipwhois(body: str) -> dict:
    payload = _obj(body)
    connection = payload.get("connection") or {}
    number = connection.get("asn")
    return {
        "asn": str(number) if number is not None else None,
        "org": connection.get("org"),
        "city": payload.get("city"),
        "country": payload.get("country_code"),
        "latitude": payload.get("latitude"),
        "longitude": payload.get("longitude"),
    }


def ipguide(body: str) -> dict:
    payload = _obj(body)
    network = payload.get("network") or {}
    system = network.get("autonomous_system") or {}
    location = payload.get("location") or {}
    number = system.get("asn")
    return {
        "prefix": network.get("cidr"),
        "asn": str(number) if number is not None else None,
        "name": system.get("organization") or system.get("name"),
        "country": system.get("country"),
        "city": location.get("city"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
    }


def bgp_tools(body: str) -> dict:
    lines = [line for line in body.splitlines() if "|" in line]
    if len(lines) < 2:
        return {}
    fields = [field.strip() for field in lines[1].split("|")]
    if len(fields) < 7:
        return {}
    return {
        "asn": fields[0] or None,
        "prefix": fields[2] or None,
        "country": fields[3] or None,
        "registry": fields[4] or None,
        "allocated": fields[5] or None,
        "name": fields[6] or None,
    }


def bgproutes(body: str) -> dict:
    payload = _obj(body)
    vp_payload = ((payload.get("vantage_points") or {}).get("data") or {})
    vps = {
        str(item.get("id")): item
        for item in (vp_payload.get("bgp") or [])
        if isinstance(item, dict) and item.get("id") is not None
    }
    rib = ((payload.get("rib") or {}).get("data") or {})
    routes: list[dict] = []
    for vp_id, entries in (rib.get("bgp") or {}).items():
        if not isinstance(entries, dict):
            continue
        vp = vps.get(str(vp_id), {})
        for prefix, values in entries.items():
            as_path = values[0] if isinstance(values, list) and values else None
            aspa_status = values[2] if isinstance(values, list) and len(values) > 2 else None
            rov_status = values[3] if isinstance(values, list) and len(values) > 3 else None
            label = (
                vp.get("org_name")
                or vp.get("ixp_name")
                or vp.get("country")
                or f"VP {vp_id}"
            )
            if vp.get("asn") is not None:
                label = f"{label} AS{vp['asn']}"
            routes.append(
                {
                    "collector": "bgproutes.io",
                    "vp_id": vp_id,
                    "vp_label": label,
                    "vp_ip": vp.get("ip"),
                    "vp_asn": vp.get("asn"),
                    "vp_country": vp.get("country"),
                    "vp_source": vp.get("source"),
                    "ixp_name": vp.get("ixp_name"),
                    "ixp_id": vp.get("ixp_id"),
                    "org_name": vp.get("org_name"),
                    "org_country": vp.get("org_country"),
                    "prefix": prefix,
                    "as_path": as_path,
                    "aspa_status": aspa_status,
                    "rov_status": rov_status,
                }
            )
    return {"routes": routes}


def routeviews_prefix(body: str) -> dict:
    routes: list[dict] = []
    for item in _list(body):
        if not isinstance(item, dict):
            continue
        peers = [peer for peer in item.get("reporting_peers") or [] if isinstance(peer, dict)]
        routes.append(
            {
                "prefix": item.get("prefix"),
                "origin_asn": item.get("origin_asn"),
                "rpki_state": item.get("rpki_state"),
                "rpki_roas": item.get("rpki_roas"),
                "peers": len(peers),
                "collectors": sorted({peer.get("collector") for peer in peers if peer.get("collector")}),
                "as_paths": sorted({peer.get("as_path") for peer in peers if peer.get("as_path")}),
                "reporting_peers": [
                    {
                        "peer_asn": peer.get("peer_asn"),
                        "peer_addr": peer.get("peer_addr"),
                        "collector": peer.get("collector"),
                        "as_path": peer.get("as_path"),
                        "communities": peer.get("communities"),
                        "timestamp": peer.get("timestamp"),
                    }
                    for peer in peers
                ],
            }
        )
    return {"routes": routes}


def routeviews_asn(body: str) -> dict:
    return {"prefixes": [item for item in _list(body) if isinstance(item, str)]}


def atlas_ping(body: str) -> dict:
    results: list[dict] = []
    for item in _list(body)[:25]:
        if not isinstance(item, dict):
            continue
        results.append(
            {
                "prb_id": item.get("prb_id"),
                "from": item.get("from"),
                "avg_rtt": item.get("avg"),
                "min_rtt": item.get("min"),
                "max_rtt": item.get("max"),
                "sent": item.get("sent"),
                "rcvd": item.get("rcvd"),
                "timestamp": item.get("timestamp"),
            }
        )
    return {"results": results}


def atlas_probes(body: str) -> dict:
    payload = _obj(body)
    results = payload.get("results") or []
    probes = [
        {"id": item.get("id"), "asn": item.get("asn_v4"), "country": item.get("country_code")}
        for item in results
        if isinstance(item, dict)
    ]
    countries: dict[str, int] = {}
    for probe in probes:
        code = probe.get("country")
        if code:
            countries[code] = countries.get(code, 0) + 1
    return {"count": payload.get("count", len(probes)), "probes": probes, "countries": countries}


def irr(body: str) -> dict:
    objects: list[dict] = []
    current: dict = {}
    for line in body.splitlines():
        if not line.strip():
            if current:
                objects.append(current)
                current = {}
            continue
        if line[0] in " \t#%":
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key in ("route", "route6"):
            current.setdefault("prefix", value)
        elif key == "origin":
            current.setdefault("origin", value)
        elif key == "descr":
            current.setdefault("descr", value)
        elif key == "source":
            current.setdefault("source", value)
    if current:
        objects.append(current)
    return {"objects": objects}


def _float(text: str) -> float | None:
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _asn_digits(text) -> str | None:
    match = re.search(r"(\d+)", text or "")
    return match.group(1) if match else None
