"""Adapter registry: what to fetch, how to parse, how to observe.

Each adapter describes a source with its dependency needs, a URL builder (or a
custom fetch callable), a structured parser, how to contribute derived context
(ASN, hostname, net_id) to downstream adapters, and how to map the parsed
result into normalized observations (topic/key/value) with provenance.
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.error
import urllib.request

import parsers
import ripe

TIMEOUT = 20
USER_AGENT = "aranya/0.0"
GLOBALPING_URL = "https://api.globalping.io/v1/measurements"
ATLAS_MEASUREMENTS_URL = "https://atlas.ripe.net/api/v2/measurements/"
ATLAS_RESULTS_URL = "https://atlas.ripe.net/api/v2/measurements/{mid}/results/"


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


def _fetch_atlas(ip: str, ctx: dict) -> tuple[int | None, str | None, str | None]:
    status, body, error = http_get(
        f"{ATLAS_MEASUREMENTS_URL}?target_ip={ip}&type=ping&status=2&page_size=50"
    )
    if error:
        return status, body, error
    try:
        measurements = json.loads(body).get("results") or []
    except ValueError:
        return status, body, "bad measurement list"
    if not measurements:
        return None, None, "no public ping measurement for this IP"
    now = int(time.time())
    ordered = sorted(measurements, key=lambda m: m.get("creation_time") or 0, reverse=True)
    for measurement in ordered[:10]:
        mid = measurement.get("id")
        if mid is None:
            continue
        url = f"{ATLAS_RESULTS_URL.format(mid=mid)}?format=json&start={now - 3600}&stop={now}"
        rstatus, rbody, rerror = http_get(url)
        if rerror:
            continue
        try:
            results = json.loads(rbody)
        except ValueError:
            continue
        if isinstance(results, list) and any(
            isinstance(item, dict) and (item.get("timestamp") or 0) >= now - 3600
            for item in results
        ):
            return rstatus, rbody, None
    return None, None, "no recent Atlas ping results"


def _fetch_irr(ip: str, ctx: dict) -> tuple[int | None, str | None, str | None]:
    prefix = ctx.get("prefix")
    if not prefix:
        return None, None, "no prefix for IRR lookup"
    try:
        conn = socket.create_connection(("whois.radb.net", 43), timeout=TIMEOUT)
        conn.sendall(f"-T route {prefix}\r\n".encode())
        chunks: list[bytes] = []
        total = 0
        while total < 262144:
            chunk = conn.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        conn.close()
        return 200, b"".join(chunks).decode("utf-8", "replace"), None
    except Exception as exc:
        return None, None, str(exc)


def _reverse(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _env(name: str) -> str | None:
    return os.environ.get(name) or None


def _mmdb_precheck(env_name: str) -> str | None:
    path = _env(env_name)
    if not path:
        return f"{env_name} not set"
    if not os.path.isfile(path):
        return f"{env_name} file not found"
    try:
        import maxminddb  # noqa: F401
    except ImportError:
        return "maxminddb not installed (pip install maxminddb)"
    return None


def _make_mmdb_fetch(env_name: str):
    def fetch(ip: str, ctx: dict) -> tuple[int | None, str | None, str | None]:
        try:
            import maxminddb
            with maxminddb.open_database(_env(env_name)) as reader:
                record = reader.get(ip)
        except Exception as exc:
            return None, None, str(exc)
        if record is None:
            return None, None, "not in database"
        return 200, json.dumps(record), None

    return fetch


def redact_url(url: str) -> str:
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.query:
        return url
    query = [
        (key, "***" if key.lower() in ("token", "key", "api_key") else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunparse(parts._replace(query=urlencode(query)))


def _first_asn(parsed: dict) -> object:
    asns = parsed.get("asns")
    return asns[0] if isinstance(asns, list) and asns else None


def _first_hostname(parsed: dict) -> object:
    hostnames = parsed.get("hostnames")
    return hostnames[0] if isinstance(hostnames, list) and hostnames else None


def _obs(topic: str, key: str, value: object) -> dict:
    return {"topic": topic, "key": key, "value": value}


def _network_info_obs(ip: str, parsed: dict) -> list[dict]:
    obs = [_obs("ownership", "prefix", parsed["prefix"])]
    obs.extend(_obs("ownership", "asn", asn) for asn in parsed["asns"])
    return obs


def _geoloc_obs(ip: str, parsed: dict) -> list[dict]:
    obs = []
    for loc in parsed["locations"]:
        if loc.get("country") == "?":
            continue
        obs.append(_obs("location", "claim", loc))
    return obs


def _as_overview_obs(ip: str, parsed: dict) -> list[dict]:
    return [
        _obs("ownership", "asn", parsed["asn"]),
        _obs("ownership", "holder", parsed["holder"]),
        _obs("ownership", "block", parsed["block"]),
        _obs("routing", "announced", parsed["announced"]),
    ]


def _asn_neighbours_obs(ip: str, parsed: dict) -> list[dict]:
    return [
        _obs("neighbours", "counts", parsed["neighbour_counts"]),
        _obs("neighbours", "list", parsed["neighbours"]),
    ]


def _ipmap_obs(ip: str, parsed: dict) -> list[dict]:
    return [_obs("location", "claim", loc) for loc in parsed["locations"]]


def _rdns_obs(ip: str, parsed: dict) -> list[dict]:
    return [_obs("identity", "hostname", parsed["hostname"])]


def _cymru_obs(ip: str, parsed: dict) -> list[dict]:
    obs: list[dict] = []
    for record in parsed["records"]:
        obs.append(_obs("ownership", "asn", record["asn"]))
        obs.append(_obs("ownership", "prefix", record["prefix"]))
        obs.append(_obs("country", "country", record["country"]))
    return obs


def _rdap_obs(ip: str, parsed: dict) -> list[dict]:
    return [
        _obs("ownership", "handle", parsed["handle"]),
        _obs("ownership", "name", parsed["name"]),
        _obs("ownership", "range", parsed["range"]),
        _obs("ownership", "status", parsed["status"]),
        _obs("country", "country", parsed["country"]),
    ]


def _internetdb_obs(ip: str, parsed: dict) -> list[dict]:
    obs = [_obs("identity", "hostname", hostname) for hostname in parsed["hostnames"]]
    obs.append(_obs("identity", "ports", parsed["ports"]))
    obs.append(_obs("identity", "cpes", parsed["cpes"]))
    obs.append(_obs("identity", "vulns", parsed["vulns"]))
    return obs


def _ipwhois_obs(ip: str, parsed: dict) -> list[dict]:
    return [
        _obs("ownership", "asn", parsed["asn"]),
        _obs("ownership", "org", parsed["org"]),
        _obs("location", "claim", {
            "city": parsed["city"],
            "country": parsed["country"],
            "latitude": parsed["latitude"],
            "longitude": parsed["longitude"],
        }),
    ]


def _ipguide_obs(ip: str, parsed: dict) -> list[dict]:
    return [
        _obs("ownership", "prefix", parsed["prefix"]),
        _obs("ownership", "asn", parsed["asn"]),
        _obs("ownership", "name", parsed["name"]),
        _obs("country", "country", parsed["country"]),
        _obs("location", "claim", {
            "city": parsed["city"],
            "country": parsed["country"],
            "latitude": parsed["latitude"],
            "longitude": parsed["longitude"],
        }),
    ]


def _globalping_obs(ip: str, parsed: dict) -> list[dict]:
    return [_obs("latency", "probe", result) for result in parsed["results"]]


def _best_route(parsed: dict) -> dict:
    best: dict = {}
    best_length = -1
    for route in parsed.get("routes") or []:
        prefix = route.get("prefix") or ""
        if "/" not in prefix:
            continue
        try:
            length = int(prefix.split("/")[1])
        except ValueError:
            continue
        if length > best_length:
            best_length = length
            best = route
    return best


def _routeviews_provides(parsed: dict) -> dict:
    best = _best_route(parsed)
    return {"asn": best.get("origin_asn"), "prefix": best.get("prefix")}


def _routeviews_obs(ip: str, parsed: dict) -> list[dict]:
    best = _best_route(parsed)
    obs: list[dict] = []
    if best.get("origin_asn") is not None:
        obs.append(_obs("ownership", "asn", str(best["origin_asn"])))
    if best.get("prefix"):
        obs.append(_obs("ownership", "prefix", best["prefix"]))
    if best.get("rpki_state"):
        obs.append(_obs("routing", "rpki", best["rpki_state"]))
    return obs


def _atlas_obs(ip: str, parsed: dict) -> list[dict]:
    return [
        _obs(
            "latency",
            "probe",
            {
                "prb_id": result.get("prb_id"),
                "avg_rtt": result.get("avg_rtt"),
                "min_rtt": result.get("min_rtt"),
                "max_rtt": result.get("max_rtt"),
            },
        )
        for result in parsed["results"]
    ]


def _atlas_probes_obs(ip: str, parsed: dict) -> list[dict]:
    obs = [_obs("probes", "count", parsed["count"])]
    obs += [_obs("probes", "country", {"country": code, "count": count}) for code, count in sorted(parsed["countries"].items())]
    return obs


def _irr_obs(ip: str, parsed: dict) -> list[dict]:
    origins: set[str] = set()
    names: set[str] = set()
    for obj in parsed["objects"]:
        origin = obj.get("origin")
        if origin:
            match = re.search(r"\d+", origin)
            if match:
                origins.add(match.group())
        descr = obj.get("descr")
        if descr and not obj.get("source", "").strip().upper().startswith("RPKI"):
            names.add(descr)
    obs = [_obs("ownership", "asn", origin) for origin in sorted(origins)]
    obs += [_obs("ownership", "name", name) for name in sorted(names)]
    return obs


def _peeringdb_net_obs(ip: str, parsed: dict) -> list[dict]:
    return [
        _obs("directory", "net_id", parsed["net_id"]),
        _obs("ownership", "name", parsed["name"]),
        _obs("directory", "website", parsed["website"]),
        _obs("directory", "info_type", parsed["info_type"]),
    ]


def _peeringdb_netfac_obs(ip: str, parsed: dict) -> list[dict]:
    return [_obs("facility", "facility", facility) for facility in parsed["facilities"]]


def _peeringdb_netixlan_obs(ip: str, parsed: dict) -> list[dict]:
    return [_obs("ix", "ixlan", item) for item in parsed["ix"]]


def _crtsh_obs(ip: str, parsed: dict) -> list[dict]:
    return [_obs("names", "certificate", cert) for cert in parsed["certificates"]]


def _ipinfo_obs(ip: str, parsed: dict) -> list[dict]:
    obs = [
        _obs("location", "claim", {
            "city": parsed["city"],
            "country": parsed["country"],
            "latitude": parsed["latitude"],
            "longitude": parsed["longitude"],
        }),
        _obs("ownership", "org", parsed["org"]),
        _obs("ownership", "asn", parsed["asn"]),
        _obs("identity", "hostname", parsed["hostname"]),
    ]
    if parsed.get("anycast") is not None:
        obs.append(_obs("routing", "anycast", parsed["anycast"]))
    return obs


def _shodan_obs(ip: str, parsed: dict) -> list[dict]:
    obs = [_obs("identity", "hostname", hostname) for hostname in parsed["hostnames"]]
    obs.append(_obs("identity", "ports", parsed["ports"]))
    obs.append(_obs("identity", "os", parsed["os"]))
    obs.append(_obs("ownership", "org", parsed["org"]))
    obs.append(_obs("ownership", "asn", parsed["asn"]))
    obs.append(_obs("location", "claim", {
        "city": parsed["city"],
        "country": parsed["country"],
        "latitude": parsed["latitude"],
        "longitude": parsed["longitude"],
    }))
    return obs


def _mmdb_obs(ip: str, parsed: dict) -> list[dict]:
    return [
        _obs("location", "claim", {
            "city": parsed["city"],
            "country": parsed["country"],
            "latitude": parsed["latitude"],
            "longitude": parsed["longitude"],
        })
    ]


def _mmdb_asn_obs(ip: str, parsed: dict) -> list[dict]:
    return [
        _obs("ownership", "asn", parsed["asn"]),
        _obs("ownership", "org", parsed["org"]),
    ]


SOURCES: list[dict] = [
    {
        "id": "ripestat.network-info",
        "upstream": "RIPE NCC",
        "evidence_class": "reported",
        "needs": [],
        "url": lambda ctx: f"https://stat.ripe.net/data/network-info/data.json?resource={ctx['ip']}",
        "parse": ripe.network_info,
        "observations": _network_info_obs,
        "provides": lambda parsed: {"asn": _first_asn(parsed)},
    },
    {
        "id": "ripestat.geoloc",
        "upstream": "RIPE NCC (embeds MaxMind/IP2Location)",
        "evidence_class": "reported",
        "needs": [],
        "url": lambda ctx: f"https://stat.ripe.net/data/geoloc/data.json?resource={ctx['ip']}",
        "parse": ripe.geoloc,
        "observations": _geoloc_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "ripestat.as-overview",
        "upstream": "RIPE NCC (RIS)",
        "evidence_class": "reported",
        "needs": ["asn"],
        "url": lambda ctx: f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{ctx['asn']}",
        "parse": ripe.as_overview,
        "observations": _as_overview_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "ripestat.asn-neighbours",
        "upstream": "RIPE NCC (RIS)",
        "evidence_class": "reported",
        "needs": ["asn"],
        "url": lambda ctx: f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{ctx['asn']}",
        "parse": ripe.asn_neighbours,
        "observations": _asn_neighbours_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "ipmap",
        "upstream": "RIPE NCC (Atlas + rDNS)",
        "evidence_class": "inferred",
        "needs": [],
        "url": lambda ctx: f"https://ipmap.ripe.net/api/v1/locate/{ctx['ip']}",
        "parse": ripe.ipmap,
        "observations": _ipmap_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "cymru.origin",
        "upstream": "Team Cymru (BGP)",
        "evidence_class": "observed-passive",
        "needs": [],
        "url": lambda ctx: (
            f"https://dns.google/resolve?name={_reverse(ctx['ip'])}.origin.asn.cymru.com&type=TXT"
        ),
        "parse": parsers.cymru,
        "observations": _cymru_obs,
        "provides": lambda parsed: {
            "asn": parsed["records"][0]["asn"] if parsed["records"] else None
        },
    },
    {
        "id": "routeviews.prefix",
        "upstream": "RouteViews",
        "evidence_class": "observed-passive",
        "needs": [],
        "url": lambda ctx: f"https://api.routeviews.org/prefix/{ctx['ip']}/32",
        "parse": parsers.routeviews_prefix,
        "observations": _routeviews_obs,
        "provides": _routeviews_provides,
    },
    {
        "id": "irr.origin",
        "upstream": "IRR (RADb)",
        "evidence_class": "reported",
        "needs": ["prefix"],
        "url": lambda ctx: f"IRR route {ctx['prefix']}",
        "fetch": _fetch_irr,
        "parse": parsers.irr,
        "observations": _irr_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "rdap",
        "upstream": "RIR",
        "evidence_class": "reported",
        "needs": [],
        "url": lambda ctx: f"https://rdap.org/ip/{ctx['ip']}",
        "parse": parsers.rdap,
        "observations": _rdap_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "ipwho.is",
        "upstream": "ipwho.is",
        "evidence_class": "reported",
        "needs": [],
        "url": lambda ctx: f"https://ipwho.is/{ctx['ip']}",
        "parse": parsers.ipwhois,
        "observations": _ipwhois_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "ip.guide",
        "upstream": "ip.guide",
        "evidence_class": "reported",
        "needs": [],
        "url": lambda ctx: f"https://ip.guide/{ctx['ip']}",
        "parse": parsers.ipguide,
        "observations": _ipguide_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "rdns.ptr",
        "upstream": "DNS",
        "evidence_class": "reported",
        "needs": [],
        "url": lambda ctx: f"PTR {ctx['ip']}",
        "fetch": _fetch_rdns,
        "parse": parsers.rdns,
        "observations": _rdns_obs,
        "provides": lambda parsed: {"hostname": parsed["hostname"]},
    },
    {
        "id": "internetdb",
        "upstream": "Shodan",
        "evidence_class": "observed-passive",
        "needs": [],
        "url": lambda ctx: f"https://internetdb.shodan.io/{ctx['ip']}",
        "parse": parsers.internetdb,
        "observations": _internetdb_obs,
        "provides": lambda parsed: {"hostname": _first_hostname(parsed)},
    },
    {
        "id": "globalping.ping",
        "upstream": "Globalping",
        "evidence_class": "observed-active",
        "needs": [],
        "url": lambda ctx: GLOBALPING_URL,
        "fetch": _fetch_globalping,
        "parse": parsers.globalping,
        "observations": _globalping_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "atlas.ping",
        "upstream": "RIPE Atlas",
        "evidence_class": "observed-active",
        "needs": [],
        "url": lambda ctx: f"{ATLAS_MEASUREMENTS_URL}?target_ip={ctx['ip']}&type=ping&status=2&page_size=50",
        "fetch": _fetch_atlas,
        "parse": parsers.atlas_ping,
        "observations": _atlas_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "atlas.probes",
        "upstream": "RIPE Atlas",
        "evidence_class": "observed-passive",
        "needs": ["asn"],
        "url": lambda ctx: f"https://atlas.ripe.net/api/v2/probes/?asn_v4={ctx['asn']}&page_size=100&fields=id,asn_v4,country_code",
        "parse": parsers.atlas_probes,
        "observations": _atlas_probes_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "peeringdb.net",
        "upstream": "PeeringDB",
        "evidence_class": "reported",
        "needs": ["asn"],
        "url": lambda ctx: f"https://www.peeringdb.com/api/net?asn={ctx['asn']}",
        "parse": parsers.peeringdb_net,
        "observations": _peeringdb_net_obs,
        "provides": lambda parsed: {"net_id": parsed["net_id"]},
    },
    {
        "id": "peeringdb.netfac",
        "upstream": "PeeringDB",
        "evidence_class": "reported",
        "needs": ["net_id"],
        "delay": 1.2,
        "url": lambda ctx: f"https://www.peeringdb.com/api/netfac?net_id={ctx['net_id']}",
        "parse": parsers.peeringdb_netfac,
        "observations": _peeringdb_netfac_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "peeringdb.netixlan",
        "upstream": "PeeringDB",
        "evidence_class": "reported",
        "needs": ["net_id"],
        "delay": 1.2,
        "url": lambda ctx: f"https://www.peeringdb.com/api/netixlan?net_id={ctx['net_id']}",
        "parse": parsers.peeringdb_netixlan,
        "observations": _peeringdb_netixlan_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "crtsh",
        "upstream": "CT logs",
        "evidence_class": "reported",
        "needs": ["hostname"],
        "url": lambda ctx: f"https://crt.sh/?q={ctx['hostname']}&output=json",
        "parse": parsers.crtsh,
        "observations": _crtsh_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "ipinfo",
        "upstream": "IPinfo (ProbeNet + registry)",
        "evidence_class": "reported",
        "needs": [],
        "precheck": lambda: None if _env("IPINFO_TOKEN") else "IPINFO_TOKEN not set",
        "url": lambda ctx: f"https://ipinfo.io/{ctx['ip']}/json?token={_env('IPINFO_TOKEN')}",
        "parse": parsers.ipinfo,
        "observations": _ipinfo_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "shodan.host",
        "upstream": "Shodan",
        "evidence_class": "observed-passive",
        "needs": [],
        "precheck": lambda: None if _env("SHODAN_API_KEY") else "SHODAN_API_KEY not set",
        "url": lambda ctx: f"https://api.shodan.io/shodan/host/{ctx['ip']}?key={_env('SHODAN_API_KEY')}",
        "parse": parsers.shodan,
        "observations": _shodan_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "maxmind.geolite2",
        "upstream": "MaxMind",
        "evidence_class": "reported",
        "needs": [],
        "precheck": lambda: _mmdb_precheck("MAXMIND_DB"),
        "url": lambda ctx: f"MAXMIND_DB {ctx['ip']}",
        "fetch": _make_mmdb_fetch("MAXMIND_DB"),
        "parse": parsers.mmdb,
        "observations": _mmdb_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "dbip.lite",
        "upstream": "DB-IP",
        "evidence_class": "reported",
        "needs": [],
        "precheck": lambda: _mmdb_precheck("DBIP_DB"),
        "url": lambda ctx: f"DBIP_DB {ctx['ip']}",
        "fetch": _make_mmdb_fetch("DBIP_DB"),
        "parse": parsers.mmdb,
        "observations": _mmdb_obs,
        "provides": lambda parsed: {},
    },
    {
        "id": "maxmind.asn",
        "upstream": "MaxMind",
        "evidence_class": "reported",
        "needs": [],
        "precheck": lambda: _mmdb_precheck("MAXMIND_ASN_DB"),
        "url": lambda ctx: f"MAXMIND_ASN_DB {ctx['ip']}",
        "fetch": _make_mmdb_fetch("MAXMIND_ASN_DB"),
        "parse": parsers.mmdb_asn,
        "observations": _mmdb_asn_obs,
        "provides": lambda parsed: {},
    },
]
