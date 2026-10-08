"""Derived analysis over a run's raw hops and enriched graph.

Pure computation, no network: everything here works on data already stored by
`probe.py` (raw hops) and `enrich.py` (geo/AS facts). The two questions answered:

- **Is a hop's TTL trustworthy?** The TTL in the graph is the probe TTL at which a
  hop answered, i.e. a traceroute inference, per flow. It is weakened when the
  same IP answers at different TTLs across flows (path change or an alias), when
  it is only seen by a single flow, or when a gap precedes it (routers in between
  that never answered).
- **Does an inter-AS edge look like a local handoff?** Geolocate both endpoint
  IPs; if they are in the same city (or within a radius), a facility the two ASes
  share and that sits in that city is a strong handoff candidate.
"""

from __future__ import annotations

import math

EARTH_RADIUS_KM = 6371.0
SAME_PLACE_KM = 300.0


def _reply_base(reply_ttl: int) -> int:
    for base in (32, 64, 128, 255):
        if reply_ttl <= base:
            return base
    return 255


def ttl_trust(hops: list[dict]) -> dict[str, dict]:
    by_ip: dict[str, dict] = {}
    for hop in hops:
        ip = hop.get("src_ip")
        if not ip:
            continue
        entry = by_ip.setdefault(ip, {"flows": set(), "ttls": set(), "reply": [], "rtts": []})
        entry["flows"].add(hop.get("flow_id"))
        if hop.get("ttl") is not None:
            entry["ttls"].add(hop["ttl"])
        if hop.get("reply_ttl") is not None:
            entry["reply"].append(hop["reply_ttl"])
        if hop.get("rtt_ms") is not None:
            entry["rtts"].append(hop["rtt_ms"])
    trust: dict[str, dict] = {}
    for ip, entry in by_ip.items():
        ttls = sorted(entry["ttls"])
        reply = min(entry["reply"]) if entry["reply"] else None
        trust[ip] = {
            "flows": len(entry["flows"]),
            "ttls": ttls,
            "ttl": ttls[0] if ttls else None,
            "consistent": len(ttls) <= 1,
            "reply_ttl": reply,
            "return_hops": (_reply_base(reply) - reply) if reply is not None else None,
            "rtt_ms": min(entry["rtts"]) if entry["rtts"] else None,
        }
    return trust


def ttl_confidence(entry: dict | None, gap_before: bool) -> tuple[str, list[str]]:
    if not entry:
        return "unknown", []
    reasons: list[str] = []
    if not entry["consistent"]:
        reasons.append("answers at ttl " + ", ".join(str(t) for t in entry["ttls"]))
    if entry["flows"] <= 1:
        reasons.append("seen by one flow only")
    if gap_before:
        reasons.append("preceded by an unanswered ttl")
    if not reasons:
        return "high", []
    if not entry["consistent"]:
        return "low", reasons
    return "medium", reasons


def rtt_km_upper(rtt_ms: float | None) -> float | None:
    if rtt_ms is None:
        return None
    return rtt_ms * 100.0


def geo_plausible(distance_km: float | None, rtt_ms: float | None, slack: float = 1.5) -> bool | None:
    if distance_km is None or rtt_ms is None:
        return None
    return distance_km <= rtt_km_upper(rtt_ms) * slack


def haversine_km(a: dict, b: dict) -> float | None:
    lat1, lon1, lat2, lon2 = a.get("latitude"), a.get("longitude"), b.get("latitude"), b.get("longitude")
    if None in (lat1, lon1, lat2, lon2):
        return None
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(h))


def _norm(value) -> str:
    return (value or "").strip().casefold()


def same_place(a: dict, b: dict) -> tuple[bool, float | None]:
    distance = haversine_km(a, b)
    if distance is not None:
        if distance <= SAME_PLACE_KM:
            return True, distance
        if _norm(a.get("city")) and _norm(a.get("city")) == _norm(b.get("city")):
            return True, distance
        return False, distance
    if _norm(a.get("city")) and _norm(a.get("city")) == _norm(b.get("city")):
        return True, None
    return False, None


def place_of(ip_geo: dict | None) -> dict:
    if not ip_geo:
        return {}
    return {"city": ip_geo.get("city"), "country": ip_geo.get("country"), "source": ip_geo.get("source")}


def facility_matches_place(facility: dict, place: dict) -> bool:
    city = _norm(facility.get("city"))
    country = _norm(facility.get("country"))
    p_city, p_country = _norm(place.get("city")), _norm(place.get("country"))
    if city and p_city and city == p_city:
        return True
    if country and p_country and country == p_country and p_city and city and (p_city in city or city in p_city):
        return True
    return False
