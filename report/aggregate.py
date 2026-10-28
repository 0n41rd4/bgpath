"""Aggregate raw observations into comparable claims.

This is the opinionated layer: it reduces raw values to short labels, clusters
sources by label, and decides consensus/dissent over independent upstreams.
Read-only projections live in views.py.
"""

from __future__ import annotations

import json
import sqlite3

from registry import sources

from report import compare, labels, views

VERDICT_MARK = {"agree": "=", "single": "·", "spread": "~", "disagree": "!"}


def upstream_map(conn: sqlite3.Connection) -> dict[str, str]:
    """source id -> independent upstream. Registry wins; stored value is the
    fallback for sources no longer in the registry. Unknowns stay distinct."""
    mapping: dict[str, str] = {}
    for source, upstream in conn.execute("SELECT DISTINCT source, upstream FROM observations"):
        mapping[source] = upstream
    for adapter in sources.SOURCES:
        mapping[adapter["id"]] = adapter.get("upstream")
    return {source: (upstream or source) for source, upstream in mapping.items()}


def _rtt(value: dict) -> float | None:
    for field in ("avg_rtt", "min_rtt", "max_rtt"):
        number = value.get(field)
        if isinstance(number, (int, float)):
            return float(number)
    return None


def _latency_label(value: object) -> str:
    if not isinstance(value, dict):
        return str(value)
    parts: list[str] = []
    city, country = value.get("city"), value.get("country")
    if city:
        parts.append(f"{city}, {country}" if country else str(city))
    elif value.get("prb_id") is not None:
        parts.append(f"probe {value['prb_id']}")
    rtt = _rtt(value)
    if rtt is not None:
        parts.append(f"{rtt:.1f} ms")
    loss = value.get("loss")
    if isinstance(loss, (int, float)) and loss:
        parts.append(f"{loss:g}% loss")
    return " · ".join(parts) or json.dumps(value, ensure_ascii=False, sort_keys=True)


def _latency_headline(source_values: dict[str, list]) -> str | None:
    rtts: list[float] = []
    probes = 0
    for values in source_values.values():
        for value in values:
            if not isinstance(value, dict):
                continue
            probes += 1
            rtt = _rtt(value)
            if rtt is not None:
                rtts.append(rtt)
    if not rtts:
        return None
    low, high = min(rtts), max(rtts)
    span = f"{low:.1f} ms" if high - low < 0.05 else f"{low:.1f}–{high:.1f} ms"
    return f"{probes} probe{'s' if probes != 1 else ''} · {span}"


def _ris_label(value: object) -> str:
    if not isinstance(value, dict):
        return str(value)
    collector = " ".join(str(part) for part in (value.get("rrc"), value.get("location")) if part)
    prefixes = value.get("prefixes") or []
    paths = value.get("paths") or []
    parts = [collector] if collector else []
    if prefixes:
        parts.append(str(prefixes[0]))
    if paths:
        parts.append(str(paths[0]))
    return " · ".join(parts) or json.dumps(value, ensure_ascii=False, sort_keys=True)


def _routeviews_label(value: object) -> str:
    if not isinstance(value, dict):
        return str(value)
    collectors = value.get("collectors") or []
    collector_text = ", ".join(str(item) for item in collectors[:2])
    if len(collectors) > 2:
        collector_text += f" +{len(collectors) - 2}"
    prefixes = value.get("prefix")
    paths = value.get("as_paths") or []
    parts = [part for part in (collector_text, prefixes, paths[0] if paths else None) if part]
    return " · ".join(str(part) for part in parts) or json.dumps(value, ensure_ascii=False, sort_keys=True)


def _bgproutes_label(value: object) -> str:
    if not isinstance(value, dict):
        return str(value)
    parts = [str(value.get("collector") or "bgproutes.io")]
    if value.get("vp_label"):
        parts.append(str(value["vp_label"]))
    if value.get("prefix"):
        parts.append(str(value["prefix"]))
    if value.get("as_path"):
        parts.append(str(value["as_path"]))
    rov = value.get("rov_status")
    if rov:
        parts.append({"V": "ROV valid", "I": "ROV invalid", "N": "ROV not found", "U": "ROV unknown"}.get(rov, f"ROV {rov}"))
    return " · ".join(parts)


def _origin_label(value: object) -> str:
    if not isinstance(value, dict):
        return str(value)
    origin = value.get("origin_asn") or value.get("asn")
    parts = [str(value.get("prefix") or "?")]
    if origin is not None:
        parts.append(f"AS{origin}")
    name = value.get("origin_name") or value.get("name")
    if name:
        parts.append(str(name))
    return " · ".join(parts)


def claim_label(topic: str, key: str, value: object, limit: int = 32) -> str:
    if topic == "latency":
        return _latency_label(value)
    if (topic, key) == ("routing", "ris"):
        return _ris_label(value)
    if (topic, key) == ("routing", "routeviews"):
        return _routeviews_label(value)
    if (topic, key) == ("routing", "bgproutes"):
        return _bgproutes_label(value)
    if (topic, key) == ("routing", "bgptools"):
        return _origin_label(value)
    if isinstance(value, dict) and ("city" in value or "latitude" in value):
        city = value.get("city")
        country = value.get("country")
        if city:
            text = f"{city}, {country}" if country else str(city)
        elif country:
            text = str(country)
        elif value.get("latitude") is not None:
            text = f"{value.get('latitude')},{value.get('longitude')}"
        else:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def labels_by_source(topic: str, key: str, source_values: dict[str, list]) -> dict[str, set[str]]:
    return {
        source: {claim_label(topic, key, value) for value in values}
        for source, values in source_values.items()
    }


def explain(summary: dict) -> str:
    if summary["topic"] == "latency":
        return "Different probes measure different paths, so compare the range, not a single value."
    verdict = summary["verdict"]
    if verdict == "single":
        return "Only one source reported this, so there is no independent confirmation."
    if verdict == "agree":
        return "All reporting upstreams agree."
    if verdict == "spread":
        return "One upstream returned several values; this is a set, not a conflict."
    if summary.get("multi"):
        return "Independent upstreams disagree; at least one also returned a set."
    return "Independent upstreams returned different values."


def summarize(topic: str, key: str, source_values: dict[str, list], upstream: dict[str, str]) -> dict:
    per_source = labels_by_source(topic, key, source_values)
    label_upstreams: dict[str, set[str]] = {}
    label_sources: dict[str, set[str]] = {}
    for source, source_labels in per_source.items():
        group = upstream.get(source, source)
        for label in source_labels:
            label_upstreams.setdefault(label, set()).add(group)
            label_sources.setdefault(label, set()).add(source)

    ranked = sorted(
        label_upstreams,
        key=lambda label: (-len(label_upstreams[label]), -len(label_sources[label]), label),
    )
    consensus = ranked[0]
    verdict = compare.classify(label_upstreams)
    if topic == "latency" and sum(len(values) for values in source_values.values()) > 1:
        verdict = "spread"
    headline = _latency_headline(source_values) if topic == "latency" else consensus
    summary = {
        "topic": topic,
        "key": key,
        "verdict": verdict,
        "verdict_label": compare.verdict_label(verdict),
        "description": labels.claim_description(topic, key),
        "group": labels.claim_group(topic, key),
        "priority": labels.claim_priority(topic, key),
        "headline": headline,
        "consensus": consensus,
        "backers": sorted(label_sources[consensus]),
        "labels": [
            {
                "label": label,
                "sources": sorted(label_sources[label]),
                "upstreams": sorted(label_upstreams[label]),
            }
            for label in ranked
        ],
        "multi": sorted(source for source, source_labels in per_source.items() if len(source_labels) > 1),
        "counts": {source: len(values) for source, values in source_values.items()},
        "source_labels": {source: sorted(source_labels) for source, source_labels in per_source.items()},
        "sources": sorted(source_values),
        "n_sources": len(source_values),
        "n_upstreams": len({upstream.get(s, s) for s in source_values}),
        "enumeration": len(source_values) == 1 and max(len(v) for v in source_values.values()) > 1,
    }
    summary["explanation"] = explain(summary)
    return summary


def cell_summaries(conn, ip: str, upstream: dict[str, str] | None = None) -> list[dict]:
    upstream = upstream if upstream is not None else upstream_map(conn)
    source_values = views.cells(conn, [ip])
    return [
        summarize(topic, key, values, upstream)
        for (_ip, topic, key), values in sorted(source_values.items())
    ]


def overview(
    conn, ips: list[str], upstream: dict[str, str] | None = None
) -> dict[tuple[str, str, str], str]:
    upstream = upstream if upstream is not None else upstream_map(conn)
    result: dict[tuple[str, str, str], str] = {}
    for (ip, topic, key), values in views.cells(conn, ips).items():
        result[(ip, topic, key)] = compare.classify(
            {
                label: {upstream.get(src, src) for src in backing}
                for label, backing in _label_sources(topic, key, values).items()
            }
        )
    return result


def agreement_profile(
    conn, ips: list[str], upstream: dict[str, str] | None = None
) -> list[dict]:
    upstream = upstream if upstream is not None else upstream_map(conn)
    stats: dict[str, dict[str, int]] = {}
    for (_ip, topic, key), values in views.cells(conn, ips).items():
        summary = summarize(topic, key, values, upstream)
        for source in values:
            row = stats.setdefault(
                source, {"cells": 0, "agree": 0, "dissent": 0, "multi": 0, "single": 0}
            )
            row["cells"] += 1
            if source in summary["multi"]:
                row["multi"] += 1
            elif summary["verdict"] == "single":
                row["single"] += 1
            elif summary["source_labels"][source][0] == summary["consensus"]:
                row["agree"] += 1
            else:
                row["dissent"] += 1
    return [{"source": source, **row} for source, row in sorted(stats.items())]


def _label_sources(topic: str, key: str, source_values: dict[str, list]) -> dict[str, set[str]]:
    labels: dict[str, set[str]] = {}
    for source, labels_of_source in labels_by_source(topic, key, source_values).items():
        for label in labels_of_source:
            labels.setdefault(label, set()).add(source)
    return labels
