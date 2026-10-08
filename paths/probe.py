"""Active path discovery.

First backend is dublin-traceroute: it probes N flow IDs (ECMP-aware) and emits
JSON with per-flow hop lists including ICMP type/code, IP-ID, NAT id and MPLS
labels. scamper (Paris/MDA) is the intended richer backend but its privilege
separation needs root; it will plug in here behind the same interface.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

TOOL = "dublin-traceroute"


def available() -> bool:
    return shutil.which(TOOL) is not None


def capture(target: str, flows: int = 3, max_ttl: int = 20, timeout: int = 120) -> dict:
    if not available():
        raise RuntimeError(f"{TOOL} not found on PATH")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [TOOL, "-n", str(flows), "-T", str(max_ttl), target],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        out = os.path.join(tmp, "trace.json")
        if not os.path.exists(out):
            raise RuntimeError(f"{TOOL} produced no trace.json")
        with open(out) as handle:
            return json.load(handle)


def parse_dublin(payload: dict) -> list[dict]:
    hops: list[dict] = []
    for flow_id, entries in (payload.get("flows") or {}).items():
        for entry in entries:
            sent_ip = ((entry.get("sent") or {}).get("ip")) or {}
            received = entry.get("received")
            hop = {
                "flow_id": int(flow_id),
                "ttl": sent_ip.get("ttl"),
                "src_ip": None,
                "probe_src": sent_ip.get("src"),
                "rtt_ms": None,
                "icmp_type": None,
                "icmp_code": None,
                "reply_ttl": None,
                "ip_id": None,
                "nat_id": entry.get("nat_id"),
                "mpls": [],
                "is_last": bool(entry.get("is_last")),
                "name": entry.get("name"),
            }
            if received:
                icmp = received.get("icmp") or {}
                ip = received.get("ip") or {}
                hop.update(
                    {
                        "src_ip": ip.get("src"),
                        "rtt_ms": entry.get("rtt_usec") / 1000.0 if entry.get("rtt_usec") is not None else None,
                        "icmp_type": icmp.get("code"),
                        "icmp_code": icmp.get("type"),
                        "reply_ttl": ip.get("ttl"),
                        "ip_id": ip.get("id"),
                        "mpls": icmp.get("mpls_labels") or [],
                    }
                )
            hops.append(hop)
    hops.sort(key=lambda hop: (hop["flow_id"], hop["ttl"] if hop["ttl"] is not None else 0))
    return hops


def run(target: str, flows: int = 3, max_ttl: int = 20, timeout: int = 120) -> tuple[str, list[dict], dict]:
    payload = capture(target, flows=flows, max_ttl=max_ttl, timeout=timeout)
    hops = parse_dublin(payload)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    vantage = next((hop["probe_src"] for hop in hops if hop.get("probe_src")), None)
    meta = {
        "flows": flows,
        "max_ttl": max_ttl,
        "flow_ids": sorted({hop["flow_id"] for hop in hops}),
        "vantage": vantage,
    }
    return started, hops, meta
