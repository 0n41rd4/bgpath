# aranya/paths — path & topology exploration

How the graph is formed. `python -m paths trace <ip>` runs an active measurement
(`paths/probe.py` — scamper Paris by default, dublin-traceroute as the
unprivileged fallback) and stores every flow's answered hops as raw records
(`paths/store.py`). `paths/graph.py` then builds the **interface layer**
topologically: the hop at TTL *n* is joined to the next answered hop in the same
flow, so when several flow IDs hit one router and leave via different next hops
the result is a diamond (ECMP) rather than a line, and unanswered TTLs become
**gap edges** instead of being collapsed away. On top of that, `paths/enrich.py`
runs the symbiotic loop: every hop IP is queried through aranya's existing
adapters (Cymru/RIPEstat) for its origin AS, each AS is expanded with its BGP
neighbours (RIPEstat `asn-neighbours`) and its facilities and IXPs (PeeringDB),
and each answer is written to its **own layer** — `origin`, `as`, `facility`,
`ix`. So a source query never rewrites topology; it only adds nodes/edges or
annotates them, and geographic hints (facility cities, rDNS) stay attributes,
never coordinates baked into the graph.

## Usage

```sh
.venv/bin/python -m paths --db paths.db trace 8.8.8.8 --tool scamper --flows 4 --maxttl 16 --enrich
.venv/bin/python -m paths --db paths.db show
.venv/bin/python -m paths --db paths.db topology <run_id>
```

`--tool dublin` uses dublin-traceroute instead. `networkx` is required for graph
building (installed in the venv); without it the probe/store/enrich tests still
run.

## Privileged tools

| Tool | Needs | Status |
|---|---|---|
| `scamper` | root (privilege separation) | via `sudo -n scamper` (NOPASSWD rule) |
| `dublin-traceroute` | `cap_net_raw` | set on the binary; runs unprivileged |
| `traceroute`, `mtr`, `nping` | none (ICMP ping sockets) | unprivileged |
| `scapy` (TTL-DNS / custom probes, later) | `CAP_NET_RAW` | privileged: run via `sudo` or setcap a helper |
| `hping3`, `paris-traceroute`, `tracebox`, `tcpdump` (if added later) | root / `cap_net_raw`(+`cap_net_admin` for capture) | privileged |
