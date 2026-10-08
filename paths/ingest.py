"""Ingest traceroute output from external tools into a run's hop table.

Each tool is normalized to the same hop shape `probe.py` produces, so several
tools/protocols can be merged into one interface graph: identical adjacencies
collapse to a single edge carrying the union of flows/protocols/tools.

Supported: `mtr` JSON (`mtr -j`), `traceroute`/`tracert` text, and the JSON
emitted by `scamper` and `dublin-traceroute`.
"""

from __future__ import annotations

import ipaddress
import json
import re

import paths.probe as probe

_TTL_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_PAREN_IP = re.compile(r"\(([0-9a-fA-F:.]+)\)")
_MS = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*ms")
TOOLS = ("mtr", "traceroute", "scamper", "dublin")


def _is_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def _hop(flow_id, ttl, src_ip, rtt_ms, name, protocol, tool):
    return {
        "flow_id": flow_id,
        "ttl": ttl,
        "src_ip": src_ip,
        "probe_src": None,
        "rtt_ms": rtt_ms,
        "icmp_type": None,
        "icmp_code": None,
        "reply_ttl": None,
        "ip_id": None,
        "nat_id": None,
        "mpls": [],
        "is_last": False,
        "name": name,
        "protocol": protocol,
        "tool": tool,
    }


def parse_mtr(payload: dict, tool: str = "mtr", protocol: str | None = "icmp", flow_id: int = 0) -> list[dict]:
    report = payload.get("report") if isinstance(payload.get("report"), dict) else payload
    hops: list[dict] = []
    for hub in report.get("hubs") or []:
        if not isinstance(hub, dict):
            continue
        host = hub.get("host")
        src_ip = host if _is_ip(host) else None
        rtt = hub.get("Avg")
        hops.append(_hop(flow_id, hub.get("count"), src_ip, rtt, None if src_ip else host, protocol, tool))
    return hops


def parse_traceroute(text: str, tool: str = "traceroute", protocol: str | None = None, flow_id: int = 0) -> list[dict]:
    hops: list[dict] = []
    for line in text.splitlines():
        match = _TTL_RE.match(line)
        if not match:
            continue
        ttl = int(match.group(1))
        rest = match.group(2).strip()
        if rest.startswith("*") or not rest:
            hops.append(_hop(flow_id, ttl, None, None, None, protocol, tool))
            continue
        parenthesized = _PAREN_IP.search(rest)
        if parenthesized:
            src_ip = parenthesized.group(1)
            name = rest.split()[0] if rest.split() else None
        else:
            token = rest.split()[0] if rest.split() else None
            src_ip = token if _is_ip(token) else None
            name = None
        rtt_match = _MS.search(rest)
        rtt = float(rtt_match.group(1)) if rtt_match else None
        hops.append(_hop(flow_id, ttl, src_ip, rtt, name, protocol, tool))
    return hops


def ingest_hops(path: str, tool: str, protocol: str | None = None) -> list[dict]:
    with open(path) as handle:
        text = handle.read()
    if tool == "mtr":
        return parse_mtr(json.loads(text), protocol=protocol or "icmp")
    if tool == "traceroute":
        return parse_traceroute(text, protocol=protocol)
    if tool == "scamper":
        objects = [json.loads(line) for line in text.splitlines() if line.strip()]
        return probe.parse_scamper([obj for obj in objects if obj.get("type") == "trace"])
    if tool == "dublin":
        return probe.parse_dublin(json.loads(text))
    raise ValueError(f"unknown tool: {tool}")
