"""Derived analysis over a run's raw hops.

Pure computation, no network. The only questions answered here: did the trace
reach the target, and what ICMP token terminated it. Everything else (origin AS,
facilities, BGP advertisement) lives in `enrich.py`.
"""

from __future__ import annotations

ICMP_LABELS = {
    (3, 0): "!N",
    (3, 1): "!H",
    (3, 2): "!P",
    (3, 3): "!P",
    (3, 4): "!F",
    (3, 5): "!S",
    (3, 9): "!X",
    (3, 10): "!X",
    (3, 13): "!X",
    (11, 0): "!T",
    (11, 1): "!T",
}


def icmp_label(icmp_type, icmp_code) -> str | None:
    return ICMP_LABELS.get((icmp_type, icmp_code))


def reachability(hops: list[dict], target: str | None) -> dict:
    observed = [hop for hop in hops if hop.get("src_ip")]
    reached = bool(target) and any(hop["src_ip"] == target for hop in observed)
    last = max(observed, key=lambda hop: hop.get("ttl") or 0) if observed else None
    return {
        "target": target,
        "reached": reached,
        "last_hop": last["src_ip"] if last else None,
        "last_ttl": last.get("ttl") if last else None,
        "error": icmp_label(last.get("icmp_type"), last.get("icmp_code")) if last else None,
    }
