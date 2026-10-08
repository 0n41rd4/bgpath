"""Alias resolution: cluster interface IPs that are the same machine.

Interfaces stay distinct nodes; a `machine` node is added and linked to each of
its interfaces by a `machine` edge carrying the method and a confidence. Only
methods that are safe offline are enabled by default:

- rDNS token: PTR names like `ae5.cr2.scl1.example` share the router token
  `cr2.scl1.example`, so the two addresses are interfaces of one router.

Deliberately NOT used: shared /30 or /31, because a point-to-point link puts the
two ends on two *different* routers. IP-ID (scamper ally) would be a second
method once its output is reliable.
"""

from __future__ import annotations

import hashlib
import re
import socket
from itertools import combinations

INTERFACE_LABEL = re.compile(
    r"^(ae|ge|xe|et|be|po|te|tu|gi|fa|fo|hu|vlan|eth|lo|irb|bundle-ether)\d+$",
    re.I,
)


def default_resolver(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def router_token(hostname: str) -> tuple[str, str] | None:
    if not hostname:
        return None
    labels = hostname.rstrip(".").split(".")
    if len(labels) < 2:
        return None
    index = 1 if INTERFACE_LABEL.match(labels[0]) and len(labels) > 2 else 0
    token = labels[index]
    return token.lower(), ".".join(labels[index + 1:]).lower()


def rdns_map(interfaces: list[str], resolver=None) -> dict[str, str]:
    resolver = resolver or default_resolver
    found: dict[str, str] = {}
    for ip in interfaces:
        hostname = resolver(ip)
        if hostname:
            found[ip] = hostname
    return found


def rdns_pairs(rdns: dict[str, str], confidence: float = 0.8) -> list[tuple]:
    groups: dict[tuple[str, str], list[str]] = {}
    for ip, hostname in rdns.items():
        token = router_token(hostname)
        if token:
            groups.setdefault(token, []).append(ip)
    pairs: list[tuple] = []
    for ips in groups.values():
        for left, right in combinations(sorted(set(ips)), 2):
            pairs.append((left, right, "rdns", confidence))
    return pairs


def _find(parent: dict[str, str], node: str) -> str:
    while parent[node] != node:
        parent[node] = parent[parent[node]]
        node = parent[node]
    return node


def clusters(pairs: list[tuple]) -> list[list[str]]:
    parent: dict[str, str] = {}

    def ensure(node: str) -> None:
        parent.setdefault(node, node)

    for left, right, _method, _confidence in pairs:
        ensure(left)
        ensure(right)
        root_left, root_right = _find(parent, left), _find(parent, right)
        if root_left != root_right:
            parent[root_left] = root_right

    groups: dict[str, list[str]] = {}
    for node in list(parent):
        groups.setdefault(_find(parent, node), []).append(node)
    return sorted((sorted(members) for members in groups.values() if len(members) > 1))


def machine_key(members: list[str]) -> str:
    digest = hashlib.sha1("|".join(sorted(members)).encode()).hexdigest()[:10]
    return f"M:{digest}"
