"""Adapter registry: what to fetch, how to parse.

Each adapter describes a source with its dependency needs, a URL builder, a
structured parser, and how to contribute derived context (e.g. the ASN) to
downstream adapters.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import ripe

TIMEOUT = 20
USER_AGENT = "aranya/0.0"


def http_get(url: str, timeout: int = TIMEOUT) -> tuple[int | None, str | None, str | None]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace"), f"HTTP {exc.code}"
    except Exception as exc:
        return None, None, str(exc)


def _first_asn(parsed: dict) -> object:
    asns = parsed.get("asns")
    return asns[0] if isinstance(asns, list) and asns else None


SOURCES: list[dict] = [
    {
        "id": "ripestat.network-info",
        "needs": [],
        "url": lambda ctx: f"https://stat.ripe.net/data/network-info/data.json?resource={ctx['ip']}",
        "parse": ripe.network_info,
        "provides": lambda parsed: {"asn": _first_asn(parsed)},
    },
    {
        "id": "ripestat.geoloc",
        "needs": [],
        "url": lambda ctx: f"https://stat.ripe.net/data/geoloc/data.json?resource={ctx['ip']}",
        "parse": ripe.geoloc,
        "provides": lambda parsed: {},
    },
    {
        "id": "ripestat.as-overview",
        "needs": ["asn"],
        "url": lambda ctx: f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{ctx['asn']}",
        "parse": ripe.as_overview,
        "provides": lambda parsed: {},
    },
    {
        "id": "ripestat.asn-neighbours",
        "needs": ["asn"],
        "url": lambda ctx: f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{ctx['asn']}",
        "parse": ripe.asn_neighbours,
        "provides": lambda parsed: {},
    },
    {
        "id": "ipmap",
        "needs": [],
        "url": lambda ctx: f"https://ipmap.ripe.net/api/v1/locate/{ctx['ip']}",
        "parse": ripe.ipmap,
        "provides": lambda parsed: {},
    },
]
