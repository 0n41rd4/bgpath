"""BGP facts from RouteViews (source-analysis layer).

The one question the graph needs answered per inter-AS hop: does the outgoing
AS originate/advertise the destination prefix? `owns` answers it by checking the
AS's RouteViews originated prefixes.
"""

from __future__ import annotations

import ipaddress

from registry import parsers, sources, store

from source import cache

ROUTEVIEWS = "https://api.routeviews.org"


def _get(url: str) -> str:
    key = cache.make("http", url)
    hit = cache.get(key)
    if hit is not None:
        return hit
    status, body, error = sources.http_get(url)
    store.record_fetch("bgp", sources.redact_url(url), status, body, error)
    if error:
        raise RuntimeError(error)
    cache.put(key, body)
    return body


def prefixes_for_asn(asn, af: int = 4) -> list[str]:
    return parsers.routeviews_asn(_get(f"{ROUTEVIEWS}/asn/{asn}?af={af}"))["prefixes"]


def owns(asn, ip: str, prefixes: list[str] | None = None) -> bool:
    if prefixes is None:
        prefixes = prefixes_for_asn(asn)
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for prefix in prefixes:
        try:
            if address in ipaddress.ip_network(prefix):
                return True
        except ValueError:
            continue
    return False
