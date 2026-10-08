# aranya/paths — path & topology exploration

How the graph is formed. `python -m paths trace <ip>` runs an active measurement
(`paths/probe.py` — scamper Paris by default, dublin-traceroute as the
unprivileged fallback) and stores every flow's answered hops as raw records
(`paths/store.py`). `paths/graph.py` then builds the **interface layer**
topologically: the hop at TTL *n* is joined to the next answered hop in the same
flow, so when several flow IDs hit one router and leave via different next hops
the result is a diamond (ECMP) rather than a line, and unanswered TTLs become
**gap edges** instead of being collapsed away. On top of that, `paths/enrich.py`
runs the symbiotic loop by calling the **source-analysis layer at the aranya
root** (`query.py`, `bgp.py`) — not the network directly: every hop IP is
resolved to its origin AS (Cymru/RIPEstat), each AS is expanded with its BGP
neighbours (RIPEstat) and its facilities/IXPs (PeeringDB), and RouteViews
announcements for the target prefix add the **announcing IP and the collector's
own interface IP** as a real BGP **session** between two interfaces (the
collector node carries lat/lon). Each fact is written to its **own layer** —
`origin`, `as`, `facility`, `ix`, `session`, `collector` — so a source query
never rewrites measured topology, only adds nodes/edges or annotates them;
geographic hints stay attributes, never coordinates baked into the graph.

**IP aliasing** (one IP used by more than one router/AS) is recorded as an
`aliased_asns` attribute on the interface node: it shows up whenever a hop or an
announcing IP is attributed to more than one AS. This is the AS-level signal;
once alias resolution (merging interfaces into machines) lands, the
interface-level case will be detected too.

## Layers

| Layer | Node | Edge | Source |
|---|---|---|---|
| `interface` | hop IP / announcing IP | hop → next hop (measured) | trace |
| `origin` | `AS<asn>` | interface → AS | Cymru / RIPEstat / RouteViews |
| `as` | `AS<neighbour>` | AS → AS | RIPEstat `asn-neighbours` |
| `session` | — | announcing IP → collector | RouteViews `reporting_peers` |
| `collector` | `COL:<name>` (interface IP + lat/lon) | — | RouteViews `/collector` |
| `facility` | `FAC:<name>` | AS → facility | PeeringDB `netfac` |
| `ix` | `IX:<id>` | AS → IX | PeeringDB `netixlan` |

## Source-analysis boundary

Reusable source work lives at the aranya root and is imported by `paths/`:
- `query.py` — generic adapter queries (`fetch_parsed`, `asn_of`, `neighbours`, PeeringDB).
- `bgp.py` — BGP facts: `announcements`, `prefixes_for_asn`, `owns`, `sessions`, `speaker_asns`.

`paths/` keeps only measurement (`probe.py`), graph construction (`graph.py`,
alias/ECMP/gap), persistence (`store.py`), and the graph-mutation glue
(`enrich.py`).

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
