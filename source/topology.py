"""AS-level topology evidence shared by the path enricher.

Everything here is built from the aranya source adapters via
`source.query.fetch_parsed`, so the exact parsers, disk cache and raw-fetch
capture used by `aranya <IP>` produce the AS paths we scan for adjacency. It is
path-agnostic: given a target IP it returns the observed AS paths toward that IP
and, given an ASN, its RIS neighbour set.
"""

from __future__ import annotations

import math
import re

from source import query


def as_path_tokens(as_path) -> list[str]:
    return re.findall(r"\d+", str(as_path or ""))


def contiguous(a, b, as_path) -> bool:
    """True when `a` and `b` appear next to each other in an AS path."""
    a, b = str(a), str(b)
    tokens = as_path_tokens(as_path)
    for left, right in zip(tokens, tokens[1:]):
        if (left == a and right == b) or (left == b and right == a):
            return True
    return False


def neighbour_map(asn) -> dict[str, dict]:
    """RIS asn-neighbours entries keyed by neighbour ASN, with their stats."""
    try:
        parsed = query.fetch_parsed("ripestat.asn-neighbours", context={"asn": str(asn)})
    except Exception:
        return {}
    return {
        str(neighbour["asn"]): neighbour
        for neighbour in parsed.get("neighbours") or []
        if neighbour.get("asn") is not None
    }


def neighbour_asns(asn) -> set[str]:
    """ASNs directly adjacent to `asn` per RIPE RIS asn-neighbours."""
    return set(neighbour_map(asn))


def target_paths(ip: str, prefix: str | None = None, with_bgproutes: bool = True) -> list[dict]:
    """AS paths toward `ip` from RouteViews, RIPE RIS and bgproutes.io.

    Each entry carries enough provenance to display on an inter-AS edge:
    the source, the raw AS path, and a short human label (collectors, RRC,
    or bgproutes vantage point).
    """
    paths: list[dict] = []

    try:
        routeviews = query.fetch_parsed("routeviews.prefix", ip)
        for route in routeviews.get("routes") or []:
            collectors = route.get("collectors") or []
            for as_path in route.get("as_paths") or []:
                paths.append(
                    {
                        "source": "RouteViews",
                        "as_path": as_path,
                        "detail": f"{len(collectors)} collectors" if collectors else "RouteViews",
                    }
                )
    except Exception:
        pass

    try:
        ris = query.fetch_parsed("ris.looking-glass", ip)
        for rrc in ris.get("rrcs") or []:
            for peer in rrc.get("peers") or []:
                as_path = peer.get("as_path")
                if not as_path:
                    continue
                location = " ".join(part for part in (rrc.get("rrc"), rrc.get("location")) if part)
                tokens = as_path_tokens(as_path)
                paths.append(
                    {
                        "source": "RIPE RIS",
                        "as_path": as_path,
                        "detail": location or "RIS",
                        "next_hop": peer.get("next_hop"),
                        "next_hop_asn": tokens[0] if tokens else None,
                    }
                )
    except Exception:
        pass

    if with_bgproutes and prefix:
        try:
            bgproutes = query.fetch_parsed(
                "bgproutes.prefix",
                ip,
                context={"prefix": prefix, "sources": "ris,routeviews,bgproutes.io", "vp_limit": 30},
            )
            for route in bgproutes.get("routes") or []:
                as_path = route.get("as_path")
                if not as_path:
                    continue
                paths.append(
                    {
                        "source": "bgproutes.io",
                        "as_path": as_path,
                        "detail": route.get("vp_label") or "bgproutes.io",
                        "vp_label": route.get("vp_label"),
                        "vp_country": route.get("vp_country"),
                        "vp_asn": route.get("vp_asn"),
                        "vp_source": route.get("vp_source"),
                        "ixp_name": route.get("ixp_name"),
                        "ixp_id": route.get("ixp_id"),
                    }
                )
        except Exception:
            pass

    return paths


def distance_km(lat1, lon1, lat2, lon2) -> float | None:
    """Haversine distance in kilometres, or None when coordinates are missing."""
    if None in (lat1, lon1, lat2, lon2):
        return None
    lat1, lon1, lat2, lon2 = map(math.radians, (lat1, lon1, lat2, lon2))
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 6371.0 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
