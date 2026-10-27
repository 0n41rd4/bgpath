"""Terminal rendering of stored observations.

Three outputs, all read-only:

- `summary_view` — the one-line identity of an IP.
- `report_view` — the main report: one IP = facts + contested claims; several
  IPs = a compact comparison table.
- `entities_view` — ownership entity detail (ASN, prefix, aliases).

Internal claim namespaces (`topic.key`) are never printed; the report uses
human labels such as "ASN", "Location", "Hostname".
"""

from __future__ import annotations

import re
from collections import Counter

from report import aggregate, entities, views
from report.labels import claim_name

__all__ = ["claim_name", "report_view", "summary_view", "entities_view"]


class Paint:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: int | None) -> str:
        if self.enabled and code:
            return f"\033[{code}m{text}\033[0m"
        return text


def _summaries(conn, ip: str) -> dict[str, dict]:
    return {f"{item['topic']}.{item['key']}": item for item in aggregate.cell_summaries(conn, ip)}


def _consensus(summaries: dict[str, dict], *keys: str) -> dict | None:
    for key in keys:
        item = summaries.get(key)
        if item and item.get("consensus"):
            return item
    return None


def _enum_count(summary: dict | None) -> int:
    return max(summary["counts"].values()) if summary and summary["counts"] else 0


def _comparable(topic: str, key: str) -> bool:
    if topic in ("ownership", "country", "location", "directory"):
        return True
    if (topic, key) in (("identity", "hostname"), ("routing", "rpki"),
                        ("routing", "announced"), ("routing", "anycast")):
        return True
    return False


def _contested(summaries: dict[str, dict]) -> list[tuple[str, dict]]:
    labels: dict[str, dict] = {}
    for item in summaries.values():
        if item["verdict"] == "disagree" and _comparable(item["topic"], item["key"]):
            labels.setdefault(claim_name(item["topic"], item["key"]), item)
    return sorted(labels.items())


COORDINATES = re.compile(r"^-?\d+(?:\.\d+)?,-?\d+(?:\.\d+)?$")


def _location_label(summary: dict | None) -> str | None:
    if not summary or not summary.get("consensus"):
        return None
    if not COORDINATES.match(summary["consensus"]):
        return summary["consensus"]
    multi = set(summary["multi"])
    for entry in summary["labels"]:
        if any(source not in multi for source in entry["sources"]) and re.search(r"[A-Za-z]", entry["label"]):
            return entry["label"]
    for entry in summary["labels"]:
        if re.search(r"[A-Za-z]", entry["label"]):
            return entry["label"]
    return summary["consensus"]


def _claim_values(summary: dict) -> list[str]:
    multi = set(summary["multi"])
    values: list[str] = []
    for entry in summary["labels"]:
        sources = [source for source in entry["sources"] if source not in multi]
        if sources:
            values.append(f"{entry['label']} ({', '.join(sources)})")
    for source in summary["multi"]:
        labels = summary["source_labels"][source]
        sample = ", ".join(labels[:3]) + ("…" if len(labels) > 3 else "")
        values.append(f"{source}*: {len(labels)} values: {sample}")
    return values


def _anycast(conn, ips: list[str]) -> list[dict]:
    found = []
    for (ip, topic, key), source_values in views.cells(conn, ips).items():
        if (topic, key) != ("location", "claim"):
            continue
        for source, values in source_values.items():
            if len(values) > 5:
                found.append({"ip": ip, "source": source, "values": len(values)})
    return sorted(found, key=lambda item: (-item["values"], item["ip"], item["source"]))


def _truncate(value, width: int) -> str:
    text = str(value)
    return text if len(text) <= width else text[: width - 1] + "…"


def _top(values):
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return max(counts, key=counts.get) if counts else None


def summary_view(conn, ip: str, color: bool = True) -> list[str]:
    summaries = _summaries(conn, ip)

    def consensus(*names):
        item = _consensus(summaries, *names)
        return item["consensus"] if item else None

    asn = consensus("ownership.asn")
    name = consensus("ownership.name", "ownership.org", "ownership.holder")
    prefix = consensus("ownership.prefix")
    hostname = consensus("identity.hostname")

    countries = []
    for values in views.cells(conn, [ip]).get((ip, "location", "claim"), {}).values():
        for value in values:
            if isinstance(value, dict):
                country = entities.country(value.get("country"))
                if country:
                    countries.append(country)
    location = _top(countries)

    parts = []
    if asn:
        parts.append(f"AS{asn}" + (f" {name}" if name else ""))
    if prefix:
        parts.append(prefix)
    if location:
        parts.append(location)
    if hostname:
        parts.append(hostname)
    if not parts:
        return [f"{ip}: no observations"]
    return [f"{ip} — " + " · ".join(parts)]


def _ip_report(conn, ip: str, paint: Paint) -> list[str]:
    summaries = _summaries(conn, ip)
    if not summaries:
        return [f"{ip}: no observations"]

    lines = [ip]
    contested = _contested(summaries)
    contested_labels = {label for label, _item in contested}

    def row(label, summary, fmt=lambda value: value):
        if summary and summary.get("consensus"):
            mark = "  [contested]" if label in contested_labels else ""
            lines.append(f"  {label:<16} {fmt(summary['consensus'])}{mark}")

    row("ASN", _consensus(summaries, "ownership.asn"), lambda value: f"AS{value}")
    network = _consensus(summaries, "ownership.name", "ownership.org", "ownership.holder")
    if network:
        network_marks = ("AS Network name", "AS Network org", "AS Network holder")
        mark = "  [contested]" if any(label in contested_labels for label in network_marks) else ""
        lines.append(f"  {'AS Network':<16} {network['consensus']}{mark}")
    row("Prefix", _consensus(summaries, "ownership.prefix"))
    row("Country", _consensus(summaries, "country.country"))
    location = _consensus(summaries, "location.claim")
    if location:
        mark = "  [contested]" if "Location" in contested_labels else ""
        lines.append(f"  {'Location':<16} {_location_label(location)}{mark}")
    row("Hostname", _consensus(summaries, "identity.hostname"))
    row("RPKI", _consensus(summaries, "routing.rpki"))
    routeviews = summaries.get("routing.routeviews")
    if routeviews and routeviews.get("headline"):
        lines.append(f"  {'RouteViews':<16} {routeviews['headline']}")

    net = _consensus(summaries, "directory.net_id")
    if net:
        kind = _consensus(summaries, "directory.info_type")
        suffix = f" · {kind['consensus']}" if kind else ""
        lines.append(f"  {'AS PeeringDB':<16} net {net['consensus']}{suffix}")

    facilities = summaries.get("facility.facility")
    ixps = summaries.get("ix.ixlan")
    if facilities or ixps:
        parts = []
        if facilities:
            parts.append(f"{_enum_count(facilities)} facilities")
        if ixps:
            parts.append(f"{_enum_count(ixps)} IXPs")
        lines.append(f"  {'AS footprint':<16} " + " · ".join(parts) + " (PeeringDB)")

    if location:
        for source in location["multi"]:
            count = len(location["source_labels"][source])
            if count > 5:
                lines.append("")
                lines.append(f"  anycast-like: {source} reports {count} location values")
                break

    if contested:
        lines.append("")
        lines.append(f"  contested ({len(contested)}):")
        mark = paint("!", 33)
        for label, item in contested:
            values = _claim_values(item)
            if len(values) > 4:
                values = values[:4] + [f"+{len(values) - 4} more"]
            lines.append(f"    {mark} {label:<18} " + " | ".join(values))
    return lines


def _multi_report(conn, ips: list[str], paint: Paint) -> list[str]:
    rows = []
    per_label: Counter = Counter()
    total_claims = 0
    contested_total = 0

    for ip in ips:
        summaries = _summaries(conn, ip)
        total_claims += len(summaries)
        contested = _contested(summaries)
        contested_total += len(contested)
        for label, _item in contested:
            per_label[label] += 1

        def consensus(*keys):
            item = _consensus(summaries, *keys)
            return item["consensus"] if item else "?"

        asn = consensus("ownership.asn")
        rows.append(
            {
                "ip": ip,
                "asn": f"AS{asn}" if asn != "?" else "?",
                "country": consensus("country.country"),
                "network": consensus("ownership.name", "ownership.org", "ownership.holder"),
                "location": _location_label(_consensus(summaries, "location.claim")) or "?",
                "hostname": consensus("identity.hostname"),
                "contested": len(contested),
            }
        )

    lines = [
        f"{'ip':<15}  {'asn':<8}  {'country':<7}  {'as network':<24}  "
        f"{'location':<24}  {'hostname':<28}  {'contested':>9}"
    ]
    for row in rows:
        count = paint(str(row["contested"]), 33) if row["contested"] else "0"
        lines.append(
            f"{row['ip']:<15}  {row['asn']:<8}  {row['country']:<7}  "
            f"{_truncate(row['network'], 24):<24}  {_truncate(row['location'], 24):<24}  "
            f"{_truncate(row['hostname'], 28):<28}  {count:>9}"
        )

    lines.append("")
    lines.append(f"{len(ips)} IP(s) · {total_claims} claims · {contested_total} contested")
    if per_label:
        top = ", ".join(f"{label} ({count})" for label, count in per_label.most_common(5))
        lines.append(f"most contested: {top}")
    anycast = _anycast(conn, ips)
    if anycast:
        item = anycast[0]
        lines.append(
            f"anycast-like: {item['ip']} · {item['source']} reports {item['values']} location values"
        )
    return lines


def report_view(conn, ips: list[str], color: bool = True) -> list[str]:
    ips = [ip for ip in ips if ip]
    if not ips:
        return ["no stored observations"]
    paint = Paint(color)
    if len(ips) == 1:
        return _ip_report(conn, ips[0], paint)
    return _multi_report(conn, ips, paint)


def entities_view(conn, ip: str, color: bool = True) -> list[str]:
    entity = entities.resolve(conn, ip)
    lines = [f"{ip}  entity"]
    if entity["asn"]:
        for index, record in enumerate(entity["asn"]):
            label = "  asn      " if index == 0 else "           "
            lines.append(f"{label}{record['asn']}  <- {', '.join(record['sources'])}")
    else:
        lines.append("  asn      -")
    lines.append(f"  country  {', '.join(entity['country']) or '-'}")
    lines.append(f"  prefix   {', '.join(entity['prefix']) or '-'}")
    lines.append(f"  range    {', '.join(entity['range']) or '-'}")
    for number, raws in entity["aliases"].items():
        groups: dict[str, list[str]] = {}
        for raw in raws:
            groups.setdefault(entities.org(raw), []).append(raw)
        lines.append(f"  aliases of AS{number}:")
        for canonical, variants in sorted(groups.items()):
            mark = "=" if len(variants) > 1 else " "
            lines.append(f"    [{mark}] {canonical:<24} <- {', '.join(variants)}")
    if entity["unlinked"]:
        lines.append(f"  unlinked names: {', '.join(entity['unlinked'])}")
    return lines
