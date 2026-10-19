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
import socket

import paths.probe as probe

_TTL_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_PAREN_IP = re.compile(r"\(([0-9a-fA-F:.]+)\)")
_MS = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*ms")
_ERROR_RE = re.compile(r"(![A-Za-z])")
_ERROR_TOKENS = {
    "!N": (3, 0),
    "!H": (3, 1),
    "!P": (3, 2),
    "!F": (3, 4),
    "!X": (3, 13),
    "!S": (3, 5),
    "!T": (11, 0),
}
TOOLS = ("mtr", "traceroute", "scamper", "dublin", "voyage")


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


def _mtr_host(host) -> tuple[str | None, str | None]:
    if not host or host == "???":
        return None, None
    parenthesized = _PAREN_IP.search(host)
    if parenthesized:
        return parenthesized.group(1), host.split("(")[0].strip() or None
    if _is_ip(host):
        return host, None
    try:
        return socket.gethostbyname(host), host
    except Exception:
        return None, host


def parse_mtr(
    payload: dict,
    tool: str = "mtr",
    protocol: str | None = "icmp",
    flow_id: int = 0,
    target: str | None = None,
) -> list[dict]:
    report = payload.get("report") if isinstance(payload.get("report"), dict) else payload
    meta = report.get("mtr") if isinstance(report.get("mtr"), dict) else {}
    dst = meta.get("dst") or target
    hops: list[dict] = []
    for hub in report.get("hubs") or []:
        if not isinstance(hub, dict):
            continue
        src_ip, name = _mtr_host(hub.get("host"))
        rtt = hub.get("Avg")
        hop = _hop(flow_id, hub.get("count"), src_ip, rtt, name, protocol, tool)
        hop["is_last"] = bool(src_ip and dst and src_ip == dst)
        hops.append(hop)
    return hops


def parse_traceroute(
    text: str,
    tool: str = "traceroute",
    protocol: str | None = None,
    flow_id: int = 0,
    target: str | None = None,
) -> list[dict]:
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
        hop = _hop(flow_id, ttl, src_ip, rtt, name, protocol, tool)
        error = _ERROR_RE.search(rest)
        if error:
            hop["icmp_type"], hop["icmp_code"] = _ERROR_TOKENS.get(error.group(1).upper(), (None, None))
        hop["is_last"] = bool(src_ip and target and src_ip == target)
        hops.append(hop)
    return hops


def ingest_hops(path: str, tool: str, protocol: str | None = None, target: str | None = None) -> list[dict]:
    with open(path) as handle:
        text = handle.read()
    if tool == "mtr":
        hops = parse_mtr(json.loads(text), protocol=protocol or "icmp", target=target)
    elif tool == "traceroute":
        hops = parse_traceroute(text, protocol=protocol, target=target)
    elif tool == "scamper":
        objects = [json.loads(line) for line in text.splitlines() if line.strip()]
        hops = probe.parse_scamper([obj for obj in objects if obj.get("type") == "trace"])
    elif tool == "dublin":
        hops = probe.parse_dublin(json.loads(text))
    elif tool == "voyage":
        hops = probe.parse_voyage(text)
    else:
        raise ValueError(f"unknown tool: {tool}")
    if target:
        for hop in hops:
            if hop.get("src_ip") == target:
                hop["is_last"] = True
    return hops
