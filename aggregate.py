"""Aggregate raw observations into comparable claims.

This is the opinionated layer: it reduces raw values to short labels, clusters
sources by label, and decides consensus/dissent over independent upstreams.
Read-only projections live in views.py.
"""

from __future__ import annotations

import json
import sqlite3

import compare
import sources
import views

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


def claim_label(topic: str, key: str, value: object, limit: int = 32) -> str:
    if isinstance(value, dict) and ("city" in value or "latitude" in value):
        city = value.get("city")
        country = value.get("country")
        if city:
            text = f"{city}, {country}" if country else str(city)
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


def summarize(topic: str, key: str, source_values: dict[str, list], upstream: dict[str, str]) -> dict:
    per_source = labels_by_source(topic, key, source_values)
    label_upstreams: dict[str, set[str]] = {}
    label_sources: dict[str, set[str]] = {}
    for source, labels in per_source.items():
        group = upstream.get(source, source)
        for label in labels:
            label_upstreams.setdefault(label, set()).add(group)
            label_sources.setdefault(label, set()).add(source)

    ranked = sorted(
        label_upstreams,
        key=lambda label: (-len(label_upstreams[label]), -len(label_sources[label]), label),
    )
    consensus = ranked[0]
    return {
        "topic": topic,
        "key": key,
        "verdict": compare.classify(label_upstreams),
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
        "multi": sorted(source for source, labels in per_source.items() if len(labels) > 1),
        "counts": {source: len(values) for source, values in source_values.items()},
        "source_labels": {source: sorted(labels) for source, labels in per_source.items()},
        "sources": sorted(source_values),
        "n_sources": len(source_values),
        "n_upstreams": len({upstream.get(s, s) for s in source_values}),
        "enumeration": len(source_values) == 1 and max(len(v) for v in source_values.values()) > 1,
    }


def cell_summaries(conn, ip: str, upstream: dict[str, str] | None = None) -> list[dict]:
    upstream = upstream if upstream is not None else upstream_map(conn)
    source_values = views.cells(conn, [ip])
    return [
        summarize(topic, key, values, upstream)
        for (_ip, topic, key), values in sorted(source_values.items())
    ]


def overview(conn, ips: list[str], upstream: dict[str, str] | None = None) -> dict[tuple[str, str, str], str]:
    upstream = upstream if upstream is not None else upstream_map(conn)
    return {
        (ip, topic, key): compare.classify(
            {
                label: {upstream.get(src, src) for src in backing}
                for label, backing in _label_sources(topic, key, values).items()
            }
        )
        for (ip, topic, key), values in views.cells(conn, ips).items()
    }


def agreement_profile(conn, ips: list[str], upstream: dict[str, str] | None = None) -> list[dict]:
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
