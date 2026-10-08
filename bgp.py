"""BGP source analysis (source analysis layer).

Turns RouteViews data into interface-level facts. A BGP announcement carries
more than an AS path: the *announcing/next-hop IP* (the peer address that spoke
to the collector) and the collector's own interface IP (with a location). So an
AS-to-AS adjacency can often be promoted to a session between two interfaces.

Also answers the feasibility question the graph needs: is an announcing IP
inside a prefix the announcing AS actually originates (`owns`)? At an IXP the
announcing IP is usually an IXP LAN address, i.e. *not* owned by that AS, which
is itself a signal.
"""

from __future__ import annotations

import ipaddress

import parsers
import sources

ROUTEVIEWS = "https://api.routeviews.org"


def _get(url: str) -> str:
    status, body, error = sources.http_get(url)
    if error:
        raise RuntimeError(error)
    return body


def announcements(prefix: str) -> list[dict]:
    return parsers.routeviews_announcements(_get(f"{ROUTEVIEWS}/prefix/{prefix}"))["routes"]


def prefixes_for_asn(asn, af: int = 4) -> list[str]:
    return parsers.routeviews_asn(_get(f"{ROUTEVIEWS}/asn/{asn}?af={af}"))["prefixes"]


def collector(name: str) -> dict:
    return parsers.routeviews_collector(_get(f"{ROUTEVIEWS}/collector/?name={name}"))


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


def speaker_asns(routes: list[dict]) -> dict[str, set[str]]:
    speakers: dict[str, set[str]] = {}
    for route in routes:
        for announcement in route.get("announcements") or []:
            addr = announcement.get("peer_addr")
            asn = announcement.get("peer_asn")
            if addr and asn is not None:
                speakers.setdefault(addr, set()).add(str(asn))
    return speakers


def sessions(routes: list[dict], cap: int = 40) -> list[dict]:
    facts: list[dict] = []
    for route in routes:
        for announcement in (route.get("announcements") or [])[:cap]:
            facts.append(
                {
                    "prefix": route.get("prefix"),
                    "origin_asn": route.get("origin_asn"),
                    "speaker_ip": announcement.get("peer_addr"),
                    "speaker_asn": announcement.get("peer_asn"),
                    "collector": announcement.get("collector"),
                    "as_path": announcement.get("as_path"),
                    "timestamp": announcement.get("timestamp"),
                }
            )
    return facts
