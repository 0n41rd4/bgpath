"""Active path discovery backends.

Two backends behind one interface:

- scamper (default): Paris traceroute, one flow per source port, emits JSON
  lines with correct ICMP type/code, IP-ID and MPLS. Needs root because of its
  privilege separation; if a passwordless `sudo -n scamper` is available it is
  used automatically, otherwise it falls back to a direct call.
- dublin-traceroute: ECMP-aware, runs unprivileged via its file capability.

Both feed the same hop shape, so the graph layer does not care which ran.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

DUBLIN = "dublin-traceroute"
SCAMPER = "scamper"
TOOLS = {"scamper": SCAMPER, "dublin": DUBLIN}

_sudo_cache: list[str] | None = None


def available(tool: str = SCAMPER) -> bool:
    return shutil.which(TOOLS.get(tool, tool)) is not None


def _sudo_allows(command: str) -> bool:
    try:
        result = subprocess.run(
            ["sudo", "-n", "-l", command], capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _scamper_command() -> list[str]:
    global _sudo_cache
    if _sudo_cache is None:
        if shutil.which(SCAMPER) is None:
            raise RuntimeError(f"{SCAMPER} not found on PATH")
        if shutil.which("sudo") is not None and _sudo_allows(SCAMPER):
            _sudo_cache = ["sudo", "-n", SCAMPER]
        else:
            _sudo_cache = [SCAMPER]
    return _sudo_cache


def capture_scamper(target: str, flows: int = 4, max_ttl: int = 20, timeout: int = 180) -> list[dict]:
    command = _scamper_command()
    args: list[str] = []
    for index in range(flows):
        args += ["-I", f"trace -P udp-paris -q 2 -w 1 -m {max_ttl} -s {40000 + index} {target}"]
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "scamper.json")
        subprocess.run(
            command + ["-p", "100", "-w", "1", "-O", "json", "-o", out] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        with open(out) as handle:
            objects = [json.loads(line) for line in handle if line.strip()]
    return [obj for obj in objects if obj.get("type") == "trace"]


def parse_scamper(traces: list[dict]) -> list[dict]:
    hops: list[dict] = []
    for trace in traces:
        flow_id = trace.get("sport")
        dst = trace.get("dst")
        for hop in trace.get("hops") or []:
            hops.append(
                {
                    "flow_id": flow_id,
                    "ttl": hop.get("probe_ttl"),
                    "src_ip": hop.get("addr"),
                    "probe_src": trace.get("src"),
                    "rtt_ms": hop.get("rtt"),
                    "icmp_type": hop.get("icmp_type"),
                    "icmp_code": hop.get("icmp_code"),
                    "reply_ttl": hop.get("reply_ttl"),
                    "ip_id": hop.get("reply_ipid"),
                    "nat_id": None,
                    "mpls": hop.get("mpls") or [],
                    "is_last": hop.get("addr") == dst,
                    "name": None,
                }
            )
    hops.sort(key=lambda hop: (hop["flow_id"] or 0, hop["ttl"] or 0))
    return hops


def capture_dublin(target: str, flows: int = 4, max_ttl: int = 20, timeout: int = 180) -> dict:
    if not available("dublin"):
        raise RuntimeError(f"{DUBLIN} not found on PATH")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [DUBLIN, "-n", str(flows), "-T", str(max_ttl), target],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        out = os.path.join(tmp, "trace.json")
        if not os.path.exists(out):
            raise RuntimeError(f"{DUBLIN} produced no trace.json")
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


def run(
    target: str,
    flows: int = 4,
    max_ttl: int = 20,
    tool: str = "scamper",
    timeout: int = 180,
) -> tuple[str, list[dict], dict]:
    if tool == "dublin":
        hops = parse_dublin(capture_dublin(target, flows=flows, max_ttl=max_ttl, timeout=timeout))
    else:
        hops = parse_scamper(capture_scamper(target, flows=flows, max_ttl=max_ttl, timeout=timeout))
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    vantage = next((hop["probe_src"] for hop in hops if hop.get("probe_src")), None)
    meta = {
        "tool": TOOLS.get(tool, tool),
        "flows": flows,
        "max_ttl": max_ttl,
        "flow_ids": sorted({hop["flow_id"] for hop in hops if hop["flow_id"] is not None}),
        "vantage": vantage,
    }
    return started, hops, meta
