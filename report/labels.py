"""Human-readable names for internal (topic, key) claims.

`topic` is an internal namespace and `key` an internal claim name; neither is
shown to users. Labels are unique so reports cannot confuse two claims.
"""

from __future__ import annotations

CLAIM_LABELS = {
    ("ownership", "asn"): "ASN",
    ("ownership", "prefix"): "Prefix",
    ("ownership", "name"): "Network name",
    ("ownership", "org"): "Network org",
    ("ownership", "holder"): "Network holder",
    ("ownership", "range"): "Address range",
    ("ownership", "block"): "Registry block",
    ("ownership", "handle"): "Registry handle",
    ("ownership", "status"): "Registry status",
    ("country", "country"): "Country",
    ("location", "claim"): "Location",
    ("routing", "rpki"): "RPKI",
    ("routing", "announced"): "Announced",
    ("routing", "anycast"): "Anycast",
    ("routing", "ris"): "RIS routes",
    ("routing", "routeviews"): "RouteViews routes",
    ("routing", "bgproutes"): "bgproutes.io routes",
    ("routing", "bgptools"): "BGP.Tools route",
    ("identity", "hostname"): "Hostname",
    ("identity", "ports"): "Ports",
    ("identity", "os"): "OS",
    ("identity", "cpes"): "CPEs",
    ("identity", "vulns"): "Vulns",
    ("names", "certificate"): "Certificates",
    ("neighbours", "counts"): "Neighbour counts",
    ("neighbours", "list"): "Neighbour list",
    ("directory", "net_id"): "PeeringDB net",
    ("directory", "website"): "Website",
    ("directory", "info_type"): "Network type",
    ("facility", "facility"): "Facilities",
    ("facility", "location"): "Facility locations",
    ("ix", "ixlan"): "IXPs",
    ("ix", "prefix"): "IX prefixes",
    ("latency", "probe"): "Latency",
    ("probes", "count"): "Atlas probes",
    ("probes", "country"): "Probe countries",
}


CLAIM_DESCRIPTIONS = {
    ("ownership", "asn"): "Autonomous systems reported as advertising this IP.",
    ("ownership", "prefix"): "Prefixes reported to cover this IP.",
    ("ownership", "name"): "Network names reported for this IP or AS.",
    ("ownership", "org"): "Organisation names reported for this IP.",
    ("ownership", "holder"): "Registry holder name for the AS.",
    ("ownership", "range"): "Address range registered for this IP.",
    ("ownership", "block"): "AS number block assigned to the AS.",
    ("ownership", "handle"): "Registry handle for this IP block.",
    ("ownership", "status"): "Registry status of this IP block.",
    ("country", "country"): "Countries reported for this IP.",
    ("location", "claim"): "Locations reported for this IP.",
    ("routing", "rpki"): "RPKI validation state for the route covering this IP.",
    ("routing", "announced"): "RIPE Stat flag that the AS announces at least one route; this is not a per-IP route match.",
    ("routing", "anycast"): "Anycast evidence reported for this IP.",
    ("routing", "ris"): "BGP routes seen by RIPE RIS collectors, including collector, peers, prefix and AS path.",
    ("routing", "routeviews"): "BGP routes seen by RouteViews collectors, including peer, prefix and AS path.",
    ("routing", "bgproutes"): "BGP routes seen by bgproutes.io’s own vantage points, excluding its RIS/RouteViews mirrors.",
    ("routing", "bgptools"): "Prefix and origin reported by bgp.tools route collectors.",
    ("identity", "hostname"): "Hostnames reported for this IP (PTR, Shodan, certificates).",
    ("identity", "ports"): "Open ports reported for this IP.",
    ("identity", "os"): "Operating systems reported for this IP.",
    ("identity", "cpes"): "CPE identifiers reported for this IP.",
    ("identity", "vulns"): "Vulnerabilities reported for this IP.",
    ("names", "certificate"): "Certificates found for hostnames on this IP.",
    ("neighbours", "counts"): "BGP neighbour counts reported for the AS.",
    ("neighbours", "list"): "BGP neighbours reported for the AS.",
    ("directory", "net_id"): "PeeringDB network record for the AS.",
    ("directory", "website"): "Website listed for the AS in PeeringDB.",
    ("directory", "info_type"): "Network type listed for the AS in PeeringDB.",
    ("facility", "facility"): "Facilities where the AS has presence (PeeringDB).",
    ("facility", "location"): "Geographic locations of the AS's facilities (PeeringDB).",
    ("ix", "ixlan"): "Internet exchange points where the AS peers (PeeringDB).",
    ("ix", "prefix"): "IX peering LAN prefixes for the AS (PeeringDB).",
    ("latency", "probe"): "Ping measurements from individual probes to this IP.",
    ("probes", "count"): "Number of RIPE Atlas probes in the AS.",
    ("probes", "country"): "Countries of RIPE Atlas probes in the AS.",
}


AS_CLAIMS = {
    ("ownership", "name"),
    ("ownership", "org"),
    ("ownership", "holder"),
    ("ownership", "block"),
    ("routing", "announced"),
    ("neighbours", "counts"),
    ("neighbours", "list"),
    ("probes", "count"),
    ("probes", "country"),
    ("directory", "net_id"),
    ("directory", "website"),
    ("directory", "info_type"),
    ("facility", "facility"),
    ("facility", "location"),
    ("ix", "ixlan"),
    ("ix", "prefix"),
}


GROUP_LABELS = {
    "core": "IP facts",
    "routes": "BGP routes",
    "as": "AS",
    "identity": "Identity",
    "latency": "Latency",
    "other": "Other",
}

CORE_CLAIMS = {
    ("ownership", "asn"),
    ("ownership", "prefix"),
    ("country", "country"),
    ("location", "claim"),
    ("identity", "hostname"),
    ("routing", "rpki"),
    ("ownership", "handle"),
    ("ownership", "range"),
    ("ownership", "status"),
}

ROUTE_CLAIMS = {
    ("routing", "ris"),
    ("routing", "routeviews"),
    ("routing", "bgproutes"),
    ("routing", "bgptools"),
    ("routing", "anycast"),
}

IDENTITY_CLAIMS = {
    ("identity", "ports"),
    ("identity", "os"),
    ("identity", "cpes"),
    ("identity", "vulns"),
    ("names", "certificate"),
}

LATENCY_CLAIMS = {("latency", "probe")}

PRIORITY = {
    ("ownership", "asn"): 1,
    ("ownership", "prefix"): 2,
    ("country", "country"): 3,
    ("location", "claim"): 4,
    ("identity", "hostname"): 5,
    ("routing", "rpki"): 6,
    ("ownership", "handle"): 7,
    ("ownership", "range"): 8,
    ("ownership", "status"): 9,
    ("routing", "ris"): 1,
    ("routing", "routeviews"): 2,
    ("routing", "bgproutes"): 3,
    ("routing", "bgptools"): 4,
    ("routing", "anycast"): 5,
    ("ownership", "name"): 1,
    ("ownership", "org"): 2,
    ("ownership", "holder"): 3,
    ("ownership", "block"): 4,
    ("routing", "announced"): 10,
    ("directory", "net_id"): 20,
    ("directory", "website"): 21,
    ("directory", "info_type"): 22,
    ("neighbours", "counts"): 30,
    ("neighbours", "list"): 31,
    ("facility", "facility"): 40,
    ("facility", "location"): 41,
    ("ix", "ixlan"): 50,
    ("ix", "prefix"): 51,
    ("probes", "count"): 60,
    ("probes", "country"): 61,
    ("identity", "ports"): 1,
    ("identity", "os"): 2,
    ("identity", "cpes"): 3,
    ("identity", "vulns"): 4,
    ("names", "certificate"): 5,
    ("latency", "probe"): 1,
}

GROUP_BASE = {"core": 0, "routes": 100, "as": 200, "identity": 300, "latency": 400, "other": 500}


def claim_group(topic: str, key: str) -> str:
    if (topic, key) in CORE_CLAIMS:
        return "core"
    if (topic, key) in ROUTE_CLAIMS:
        return "routes"
    if (topic, key) in AS_CLAIMS:
        return "as"
    if (topic, key) in IDENTITY_CLAIMS:
        return "identity"
    if (topic, key) in LATENCY_CLAIMS:
        return "latency"
    return "other"


def claim_priority(topic: str, key: str) -> int:
    group = claim_group(topic, key)
    return GROUP_BASE[group] * 100 + PRIORITY.get((topic, key), 99)



def claim_name(topic: str, key: str) -> str:
    label = CLAIM_LABELS.get((topic, key), key.replace("_", " ").capitalize())
    return f"AS {label}" if (topic, key) in AS_CLAIMS else label


def claim_description(topic: str, key: str) -> str:
    return CLAIM_DESCRIPTIONS.get((topic, key), "")
