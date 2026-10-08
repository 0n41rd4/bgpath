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

## Visualisation

`python -m paths html [run_id] -o paths.html` writes a self-contained page. It is
scan-centric: **edges are packet traversal only** (the measured hop chain, with
ECMP branches solid and unanswered-TTL gaps dashed), and cross-layer facts are
shown by **containment** — hops are grouped into AS boxes, and aliased hops are
bracketed as a "same machine" box — instead of crossing edges. Hover gives a
tooltip; click opens a panel with the node/edge attributes and a source-of-truth
link.

Cross-layer detail is **relevance-filtered, with no extra queries**. Each origin
AS's PeeringDB IXPs and facilities are already fetched once (cached), so:

- an **inter-AS traversal edge** carries a *suspected handoff*: the **intersection**
  of the two ASes' IXP (and facility) sets — i.e. where they plausibly interconnect.
  It is drawn as a coloured chip on the edge (`IX <name>` or `FAC ×n`), and clicking
  the edge lists the exact IXPs/facilities. If the intersection is empty it says so
  (likely transit or private interconnect).
- an **AS box** lists only the *suspected* IXPs/facilities (shared with a scanned
  neighbour) plus the total count — not the AS's full portfolio (Google's 135
  facilities collapse to the 3 that matter).
- a **hop** is matched directly against its AS's PeeringDB peering-LAN IPs
  (`netixlan` `ipaddr4`/`ipaddr6`); a match is flagged with an IXP dot and named on
  click. Hops otherwise report their AS, aliased ASes and machine.

All of this reuses the same cached PeeringDB responses, so the intersection and the
port match cost nothing extra.

## Analysis

`paths/analysis.py` adds two derived, query-free analyses (rendered in the page):

- **TTL trust.** The `ttl` in the graph is the probe TTL at which a hop answered —
  an active-traceroute inference, per flow (scamper Paris / dublin). It is marked
  `high` when an IP answers at one TTL across several flows with no preceding gap,
  `medium` when only one flow saw it or a gap precedes it, and `low` when the same
  IP answers at different TTLs across flows (path change or an alias). The page
  draws medium/low hops with a dashed/red border and reports the ICMP reply TTL
  (from the probe) as a cross-check. Traceroute is the right base tool here;
  independent confirmation comes from RIPE Atlas / Globalping measurements from
  other vantages, and middlebox-aware probing (Paris, tracebox) where needed.
- **Geolocated handoff.** Both endpoint IPs of an inter-AS edge are geolocated with
  the existing sources (MaxMind/DB-IP → ipwho.is → RIPEstat `geoloc`, cached). If
  the two locations match (same city, or within ~300 km), the edge is flagged as a
  local handoff, and any facility of either AS in that city is suspected — in
  addition to the PeeringDB shared-facility intersection. Suspects carry their
  method (`shared`, `geo`, or `shared+geo`).

AS boxes show the AS **name** (PeeringDB / RIPEstat) and, when available, the
number of **RIPE Atlas probes** in that AS by country (`atlas.probes`), i.e.
evidence that the AS is present where we suspect it.

- **RTT vs geolocation.** Each hop carries `min_rtt_ms`; one-way distance is
  bounded by `rtt_ms × 100 km` (fiber). A suspected handoff whose geolocated
  distance exceeds that bound is flagged implausible, and the hop with the
  largest RTT (the long-haul segment) is marked — if the AS also changes there,
  that is the real handoff hop, stronger than intersecting facility lists.
- **BGP advertisement correlation.** RouteViews announcements for the target
  prefix are grouped per collector (each with coordinates), giving where the
  prefix is seen and the AS paths there. A suspected facility is supported by
  `bgp` when a collector where the prefix is seen is within 100 km, or by
  `bgp-country` when one is in the same country; a facility that is only
  `geo`-suspected (no shared membership, no BGP reach) is flagged **weak** and
  can be ruled out. Facility coordinates come from PeeringDB `fac` and IX
  peering-LAN prefixes from `ixpfx`, fetched only for candidate IXPs/facilities
  (shared or matching a geolocated hop city) so no run fans out over an AS's
  full portfolio.

## Layers

| Layer | Node | Edge | Source |
|---|---|---|---|
| `interface` | hop IP / announcing IP | hop → next hop (measured) | trace |
| `origin` | `AS<asn>` | interface → AS | Cymru / RIPEstat / RouteViews |
| `as` | `AS<neighbour>` | AS → AS | RIPEstat `asn-neighbours` |
| `session` | — | announcing IP → collector | RouteViews `reporting_peers` |
| `collector` | `COL:<name>` (interface IP + lat/lon) | — | RouteViews `/collector` |
| `facility` | `FAC:<name>` | AS → facility | PeeringDB `netfac` |
| `ix` | `IX:<id>` | AS → IX (carries the AS's peering-LAN `ipaddr4`/`ipaddr6`) | PeeringDB `netixlan` |

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

## Many tools, one graph

A single tool sees one slice of the path. Run several protocols/tools and let them
aggregate: identical adjacencies collapse into one edge carrying the union of
`flows`, `protocols` and `tools`, so the graph grows without becoming redundant.

Built-in multi-protocol scamper (Paris), one run:

```sh
.venv/bin/python -m paths --db paths.db trace 8.8.8.8 --protocols udp,icmp,tcp --flows 3 --enrich
```

External tools, ingested into the same run (`--run-id` appends, rebuilding the
interface layer from all hops):

```sh
mtr -j -c 5 8.8.8.8 > mtr.json
traceroute -n 8.8.8.8 > tr.txt
.venv/bin/python -m paths --db paths.db ingest mtr.json --tool mtr        --protocol icmp --run-id <id>
.venv/bin/python -m paths --db paths.db ingest tr.txt  --tool traceroute --protocol udp  --run-id <id>
```

`--tool` accepts `mtr` (JSON), `traceroute` (text), `scamper` (JSON lines) and
`dublin` (JSON). Tools worth installing, each adding a different vantage on
ECMP/middleboxes: `mtr`, `traceroute`, `paris-traceroute`, `tracebox`, `hping3`,
`nping`; `scamper` and `dublin-traceroute` are already used. Different protocols
routinely take different paths (e.g. ICMP vs UDP to 8.8.8.8 hit different Google
edges), which is exactly the signal aggregation exposes.

## Testing & rate limits

Repeated runs would hammer RIPEstat / PeeringDB / RouteViews, so source-analysis
responses are cached on disk: `PATHS_CACHE` (dir, default
`~/.cache/aranya/paths`; `off` to disable) and `PATHS_CACHE_TTL` (seconds,
default 86400). Enrichment parts switch off per run:

```sh
--no-sessions    # skip RouteViews BGP sessions
--no-peeringdb   # skip PeeringDB facilities/IXPs
--no-neighbours  # skip RIPEstat AS neighbours
--no-alias       # skip rDNS alias resolution
--no-geo         # skip hop geolocation
--no-probes      # skip RIPE Atlas probe counts
--no-cache       # bypass the cache for this run
```

or with env vars `PATHS_NO_SESSIONS` / `PATHS_NO_PEERINGDB` / `PATHS_NO_NEIGHBOURS`
/ `PATHS_NO_ALIAS` / `PATHS_NO_GEO` / `PATHS_NO_PROBES` = `1`. A 4-flow scamper trace runs with a 1s wait and 100 pps,
which cuts it from ~65s to ~10s; enrichment from cache is a few seconds.

## Privileged tools

| Tool | Needs | Status |
|---|---|---|
| `scamper` | root (privilege separation) | via `sudo -n scamper` (NOPASSWD rule) |
| `dublin-traceroute` | `cap_net_raw` | set on the binary; runs unprivileged |
| `traceroute`, `mtr`, `nping` | none (ICMP ping sockets) | unprivileged |
| `scapy` (TTL-DNS / custom probes, later) | `CAP_NET_RAW` | privileged: run via `sudo` or setcap a helper |
| `hping3`, `paris-traceroute`, `tracebox`, `tcpdump` (if added later) | root / `cap_net_raw`(+`cap_net_admin` for capture) | privileged |
