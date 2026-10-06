"""Adapter registry: what to fetch, how to parse.

Each adapter describes a source with its dependency needs, a URL builder (or a
custom fetch callable), a structured parser, and how to contribute derived
context (ASN, hostname, net_id) to downstream adapters.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request

import parsers
import ripe

TIMEOUT = 20
USER_AGENT = "aranya/0.0"
GLOBALPING_URL = "https://api.globalping.io/v1/measurements"


def http_get(url: str, timeout: int = TIMEOUT, retries: int = 2) -> tuple[int | None, str | None, str | None]:
    last_error: str | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", "replace")
                if status == 429 or status >= 500:
                    last_error = f"HTTP {status}"
                else:
                    return status, body, None
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode("utf-8", "replace")
            if status == 429 or status >= 500:
                last_error = f"HTTP {status}"
            else:
                return status, body, f"HTTP {status}"
        except Exception as exc:
            last_error = str(exc)
        if attempt < retries:
            time.sleep(attempt + 1)
    return None, None, last_error


def _fetch_rdns(ip: str, ctx: dict) -> tuple[int | None, str | None, str | None]:
    try:
        return 200, socket.gethostbyaddr(ip)[0], None
    except Exception as exc:
        return None, None, str(exc)


def _fetch_globalping(ip: str, ctx: dict) -> tuple[int | None, str | None, str | None]:
    payload = {"type": "ping", "target": ip, "limit": 2, "locations": [{"magic": "world"}]}
    req = urllib.request.Request(
        GLOBALPING_URL,
        data=json.dumps(payload).encode(),
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            created = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace"), f"HTTP {exc.code}"
    except Exception as exc:
        return None, None, str(exc)

    measurement_id = created.get("id")
    if not measurement_id:
        return None, None, "no measurement id returned"

    for _ in range(10):
        time.sleep(1)
        status, body, error = http_get(f"{GLOBALPING_URL}/{measurement_id}")
        if error:
            return status, body, error
        try:
            if json.loads(body).get("status") in ("finished", "failed"):
                return status, body, None
        except ValueError:
            return status, body, "bad result body"
    return None, None, "globalping polling timed out"


def _reverse(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _first_asn(parsed: dict) -> object:
    asns = parsed.get("asns")
    return asns[0] if isinstance(asns, list) and asns else None


def _first_hostname(parsed: dict) -> object:
    hostnames = parsed.get("hostnames")
    return hostnames[0] if isinstance(hostnames, list) and hostnames else None


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
    {
        "id": "cymru.origin",
        "needs": [],
        "url": lambda ctx: (
            f"https://dns.google/resolve?name={_reverse(ctx['ip'])}.origin.asn.cymru.com&type=TXT"
        ),
        "parse": parsers.cymru,
        "provides": lambda parsed: {
            "asn": parsed["records"][0]["asn"] if parsed["records"] else None
        },
    },
    {
        "id": "rdap",
        "needs": [],
        "url": lambda ctx: f"https://rdap.org/ip/{ctx['ip']}",
        "parse": parsers.rdap,
        "provides": lambda parsed: {},
    },
    {
        "id": "rdns.ptr",
        "needs": [],
        "url": lambda ctx: f"PTR {ctx['ip']}",
        "fetch": _fetch_rdns,
        "parse": parsers.rdns,
        "provides": lambda parsed: {"hostname": parsed["hostname"]},
    },
    {
        "id": "internetdb",
        "needs": [],
        "url": lambda ctx: f"https://internetdb.shodan.io/{ctx['ip']}",
        "parse": parsers.internetdb,
        "provides": lambda parsed: {"hostname": _first_hostname(parsed)},
    },
    {
        "id": "globalping.ping",
        "needs": [],
        "url": lambda ctx: GLOBALPING_URL,
        "fetch": _fetch_globalping,
        "parse": parsers.globalping,
        "provides": lambda parsed: {},
    },
    {
        "id": "peeringdb.net",
        "needs": ["asn"],
        "url": lambda ctx: f"https://www.peeringdb.com/api/net?asn={ctx['asn']}",
        "parse": parsers.peeringdb_net,
        "provides": lambda parsed: {"net_id": parsed["net_id"]},
    },
    {
        "id": "peeringdb.netfac",
        "needs": ["net_id"],
        "delay": 1.2,
        "url": lambda ctx: f"https://www.peeringdb.com/api/netfac?net_id={ctx['net_id']}",
        "parse": parsers.peeringdb_netfac,
        "provides": lambda parsed: {},
    },
    {
        "id": "peeringdb.netixlan",
        "needs": ["net_id"],
        "delay": 1.2,
        "url": lambda ctx: f"https://www.peeringdb.com/api/netixlan?net_id={ctx['net_id']}",
        "parse": parsers.peeringdb_netixlan,
        "provides": lambda parsed: {},
    },
    {
        "id": "crtsh",
        "needs": ["hostname"],
        "url": lambda ctx: f"https://crt.sh/?q={ctx['hostname']}&output=json",
        "parse": parsers.crtsh,
        "provides": lambda parsed: {},
    },
]
