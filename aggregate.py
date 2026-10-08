"""Aggregate raw observations into comparable claims.

This is the opinionated layer: it reduces raw values to short labels, clusters
sources by label, and decides consensus/dissent. It also produces the cross-IP
source profile. Read-only projections live in views.py.
"""

from __future__ import annotations

import json

import compare
import views

VERDICT_MARK = {"agree": "=", "spread": "~", "disagree": "!"}


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


def claims(topic: str, key: str, source_values: dict[str, list]) -> tuple[dict[str, set[str]], set[str]]:
    labels: dict[str, set[str]] = {}
    multi: set[str] = set()
    for source, values in source_values.items():
        seen = {claim_label(topic, key, value) for value in values}
        if len(seen) > 1:
            multi.add(source)
        for label in seen:
            labels.setdefault(label, set()).add(source)
    return labels, multi


def summarize(topic: str, key: str, source_values: dict[str, list]) -> dict:
    labels, multi = claims(topic, key, source_values)
    ranked = sorted(labels.items(), key=lambda item: (-len(item[1]), item[0]))
    consensus = ranked[0][0]
    return {
        "topic": topic,
        "key": key,
        "verdict": compare.classify(labels),
        "consensus": consensus,
        "backers": sorted(labels[consensus]),
        "labels": ranked,
        "multi": multi,
        "counts": {source: len(values) for source, values in source_values.items()},
        "source_labels": {
            source: sorted({claim_label(topic, key, value) for value in values})
            for source, values in source_values.items()
        },
        "enumeration": len(source_values) == 1 and max(len(v) for v in source_values.values()) > 1,
        "sources": sorted(source_values),
    }


def cell_summaries(conn, ip: str) -> list[dict]:
    source_values = views.cells(conn, [ip])
    out = []
    for (_ip, topic, key), values in sorted(source_values.items()):
        out.append(summarize(topic, key, values))
    return out


def overview(conn, ips: list[str]) -> dict[tuple[str, str, str], str]:
    source_values = views.cells(conn, ips)
    return {(ip, topic, key): compare.classify(claims(topic, key, values)[0])
            for (ip, topic, key), values in source_values.items()}


def profile(conn, ips: list[str]) -> list[dict]:
    source_values = views.cells(conn, ips)
    stats: dict[str, dict[str, int]] = {}
    for (_ip, topic, key), values in source_values.items():
        labels, multi = claims(topic, key, values)
        consensus = sorted(labels.items(), key=lambda item: (-len(item[1]), item[0]))[0][0]
        for source in values:
            row = stats.setdefault(source, {"cells": 0, "agree": 0, "dissent": 0, "multi": 0})
            row["cells"] += 1
            if source in multi:
                row["multi"] += 1
            elif source in labels.get(consensus, set()):
                row["agree"] += 1
            else:
                row["dissent"] += 1
    return [{"source": source, **row} for source, row in sorted(stats.items())]
