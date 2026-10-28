"""AS-level routing facts derived from the stored observations.

Read-only: everything here comes from the `observations` table (populated by the
`aranya <IP>` run), so the report can show the announcement picture without
another fetch — how many prefixes the origin AS announces, which AS is the
upstream into it, the BGP next-hops (RIS), and where the prefix was observed
(RouteViews collectors, RIS RRCs, bgproutes.io vantage points).
"""

from __future__ import annotations

import json
import sqlite3


def _count_upstream(upstream: dict[str, int], as_path: str | None, origin: str | None) -> None:
    if not as_path or not origin:
        return
    tokens = as_path.split()
    if tokens and tokens[-1] == origin and len(tokens) >= 2:
        upstream[tokens[-2]] = upstream.get(tokens[-2], 0) + 1


def routing_summary(conn: sqlite3.Connection, ip: str) -> dict:
    origin = None
    announced = None
    upstream: dict[str, int] = {}
    next_hops: list[str] = []
    observers: dict[tuple[str, str], dict] = {}

    for topic, key, value in conn.execute(
        "SELECT topic, key, value FROM observations WHERE ip = ?", (ip,)
    ):
        if topic == "ownership" and key == "asn" and origin is None:
            try:
                origin = str(json.loads(value))
            except (TypeError, ValueError):
                origin = None
            continue
        if topic != "routing":
            continue
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            continue
        if key == "announced-count":
            if isinstance(value, (int, float)):
                announced = int(value)
            continue
        if not isinstance(value, dict):
            continue

        if key == "ris":
            location = " ".join(part for part in (value.get("rrc"), value.get("location")) if part)
            if location:
                observers.setdefault(("RIPE RIS", location), {})
            for next_hop in value.get("next_hops") or []:
                if next_hop not in next_hops:
                    next_hops.append(next_hop)
            for as_path in value.get("paths") or []:
                _count_upstream(upstream, as_path, origin)
            continue
        if key == "routeviews":
            for collector in value.get("collectors") or []:
                observers.setdefault(("RouteViews", collector), {})
            for as_path in value.get("as_paths") or []:
                _count_upstream(upstream, as_path, origin)
            continue
        if key == "bgproutes":
            _count_upstream(upstream, value.get("as_path"), origin)
            location = value.get("ixp_name") or value.get("vp_label")
            if location:
                observers.setdefault(
                    ("bgproutes.io", location),
                    {"country": value.get("vp_country"), "org": value.get("org_name")},
                )
            continue

    top_upstream = max(upstream, key=lambda asn: (upstream[asn], -int(asn)), default=None)
    return {
        "origin_asn": origin,
        "announced": announced,
        "upstream_as": top_upstream,
        "next_hops": next_hops,
        "observers": [
            {"source": source, "location": location, **(extra or {})}
            for (source, location), extra in observers.items()
        ],
    }
