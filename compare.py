"""Side-by-side comparison of observations, grouped per topic/key.

This is the first comparison layer: for each (topic, key), collect every
source's value and classify how the sources line up. No scoring or merging;
it only surfaces where sources agree or disagree.

Verdicts:
  agree    one distinct value (all sources, or a single source)
  spread   several distinct values, all from one source (e.g. anycast claims)
  disagree several distinct values from more than one source
"""

from __future__ import annotations


def group(conn, ip: str) -> dict[tuple[str, str], dict[str, set[str]]]:
    rows = conn.execute(
        "SELECT topic, key, value, source FROM observations WHERE ip = ? ORDER BY topic, key, value",
        (ip,),
    ).fetchall()
    grouped: dict[tuple[str, str], dict[str, set[str]]] = {}
    for topic, key, value, source in rows:
        grouped.setdefault((topic, key), {}).setdefault(value, set()).add(source)
    return grouped


def classify(values: dict[str, set[str]]) -> str:
    groups = {group for groups in values.values() for group in groups}
    if len(values) == 1:
        return "single" if len(groups) == 1 else "agree"
    if len(groups) == 1:
        return "spread"
    return "disagree"


def summarize(conn, ip: str) -> list[dict]:
    result = []
    for (topic, key), values in group(conn, ip).items():
        result.append(
            {
                "topic": topic,
                "key": key,
                "verdict": classify(values),
                "values": {value: sorted(sources) for value, sources in values.items()},
            }
        )
    return result
