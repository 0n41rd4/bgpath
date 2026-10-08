"""Cross-IP analysis over the stored observations.

Where views/aggregate describe one IP at a time, this reduces the whole store
to patterns: which claims are contested, which sources conform, where a single
source enumerates many locations (anycast-like). Read-only.
"""

from __future__ import annotations

from collections import Counter

import aggregate
import views


def stats(conn, ips: list[str] | None = None) -> dict:
    ips = ips if ips is not None else views.ips(conn)
    upstream = aggregate.upstream_map(conn)
    cells = views.cells(conn, ips)

    verdicts: Counter = Counter()
    per_key: dict[tuple[str, str], dict] = {}
    anycast: list[dict] = []
    for (ip, topic, key), source_values in cells.items():
        summary = aggregate.summarize(topic, key, source_values, upstream)
        verdict = summary["verdict"]
        verdicts[verdict] += 1
        row = per_key.setdefault((topic, key), {"cells": 0, "contested": 0, "verdicts": Counter()})
        row["cells"] += 1
        row["verdicts"][verdict] += 1
        if verdict in ("disagree", "spread"):
            row["contested"] += 1
        if (topic, key) == ("location", "claim"):
            for source, values in source_values.items():
                if len(values) > 5:
                    anycast.append({"ip": ip, "source": source, "values": len(values)})

    disagreements = [
        {
            "topic": topic,
            "key": key,
            "cells": row["cells"],
            "contested": row["contested"],
            "rate": row["contested"] / row["cells"],
            "verdicts": dict(row["verdicts"]),
        }
        for (topic, key), row in per_key.items()
    ]
    disagreements.sort(key=lambda d: (-d["rate"], -d["contested"], d["topic"], d["key"]))

    anycast.sort(key=lambda a: (-a["values"], a["ip"], a["source"]))

    return {
        "ips": ips,
        "claims": sum(verdicts.values()),
        "verdicts": dict(verdicts),
        "disagreements": disagreements,
        "anycast": anycast,
        "sources": aggregate.agreement_profile(conn, ips, upstream),
    }
