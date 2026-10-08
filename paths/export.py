"""Render a run's graph as a self-contained, layered HTML page.

Layers become columns (interface -> machine -> as -> collector -> facility -> ix)
so the topology reads left to right. Every node/edge carries its attributes and,
where known, a `source_url` back to the source of truth; BGP session edges carry
the announcement that produced them (collector, as_path, prefix, peer, time).
"""

from __future__ import annotations

import json
from pathlib import Path

TEMPLATE = Path(__file__).parent / "template.html"

NODE_LAYERS = ["interface", "machine", "as", "collector", "facility", "ix"]
COLUMN = {layer: index for index, layer in enumerate(NODE_LAYERS)}
COLUMN_GAP = 240
ROW_GAP = 54
TOP = 40

LABELS = {
    "interface": "interface",
    "machine": "machine",
    "as": "AS",
    "collector": "collector",
    "facility": "facility",
    "ix": "IXP",
}


def _label(node: dict) -> str:
    attrs = node["attrs"]
    if node["layer"] == "as":
        return node["key"]
    if node["layer"] == "collector":
        return attrs.get("name") or node["key"]
    if node["layer"] in ("facility", "ix"):
        return attrs.get("name") or node["key"]
    if node["layer"] == "machine":
        return f"machine ({len(attrs.get('interfaces') or [])} ifaces)"
    return node["key"]


def _load(conn, run_id: str) -> dict:
    run = conn.execute(
        "SELECT run_id, target, src_ip, tool, started_at FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    nodes: dict[str, dict] = {}
    for _node_id, layer, key, attrs in conn.execute("SELECT node_id, layer, key, attrs FROM nodes"):
        nodes[key] = {"id": key, "layer": layer, "key": key, "attrs": json.loads(attrs or "{}")}
    edges: list[dict] = []
    for layer, src, dst, ttl, count, min_rtt, attrs in conn.execute(
        "SELECT layer, src, dst, ttl, count, min_rtt_ms, attrs FROM edges WHERE run_id = ? "
        "ORDER BY layer, src, dst",
        (run_id,),
    ):
        data = json.loads(attrs or "{}")
        for endpoint in (src, dst):
            nodes.setdefault(endpoint, {"id": endpoint, "layer": "interface", "key": endpoint, "attrs": {}})
        edges.append(
            {
                "id": f"{layer}:{src}->{dst}",
                "source": src,
                "target": dst,
                "layer": layer,
                "ttl": ttl,
                "count": count,
                "min_rtt_ms": min_rtt,
                "attrs": data,
                "source_url": data.get("source_url"),
            }
        )
    return {
        "run": {"run_id": run[0], "target": run[1], "vantage": run[2], "tool": run[3], "started_at": run[4]} if run else {"run_id": run_id},
        "nodes": nodes,
        "edges": edges,
    }


def _layout(nodes: dict[str, dict], edges: list[dict]) -> None:
    ttl: dict[str, int] = {}
    for edge in edges:
        if edge["layer"] == "interface" and edge["ttl"] is not None:
            ttl[edge["target"]] = min(ttl.get(edge["target"], 10 ** 9), edge["ttl"])
    by_layer: dict[str, list[dict]] = {}
    for node in nodes.values():
        by_layer.setdefault(node["layer"], []).append(node)
    for layer, items in by_layer.items():
        if layer == "interface":
            items.sort(key=lambda node: (ttl.get(node["id"], 10 ** 9), node["id"]))
        else:
            items.sort(key=lambda node: node["id"])
        column_x = COLUMN.get(layer, len(NODE_LAYERS)) * COLUMN_GAP + 80
        tallest = max(len(items) for items in by_layer.values())
        offset = (tallest - len(items)) * ROW_GAP / 2
        for index, node in enumerate(items):
            node["x"] = column_x
            node["y"] = TOP + offset + index * ROW_GAP


def build(conn, run_id: str) -> dict:
    data = _load(conn, run_id)
    for node in data["nodes"].values():
        node["label"] = _label(node)
        node["source_url"] = node["attrs"].get("source_url")
    _layout(data["nodes"], data["edges"])
    data["nodes"] = list(data["nodes"].values())
    data["node_layers"] = NODE_LAYERS
    data["labels"] = LABELS
    return data


def _embed(data: dict) -> str:
    text = json.dumps(data, ensure_ascii=False, sort_keys=True)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_html(conn, run_id: str) -> str:
    data = build(conn, run_id)
    template = TEMPLATE.read_text()
    return template.replace("/*__PATHS_DATA__*/", _embed(data))
