# aranya/paths — path & topology exploration

`python -m paths trace <ip>` (or `aranya path <ip>`) pings the destination, then
traceroutes it regardless of the ping result, with **every available tool**:
scamper, dublin-traceroute, voyage, mtr and traceroute. Each tool is stored as its
own run, and the default output is an HTML report with **one graph per tool** —
tools can disagree, so they are never merged.

## Flow

1. **ping** — `probe.capture_ping` (system `ping -c N -n`), stored in the run meta.
2. **traceroute** — all available tools, each its own run; `--maxttl` defaults to
   `32` because long paths often exceed the usual 20. If a trace hits that cap
   without reaching the target, it is retried **once** at TTL `64` (not `mtr`).
   `--tools` limits the set, and `ingest` imports previously-captured output.
3. **graph** — `graph.py` joins each flow's answered hops into an interface
   topology. Missing TTLs are bridged only within the same flow; edges are never
   mixed across flows. If one flow has several replies at the same TTL, the best
   RTT is kept instead of drawing every reply to every next hop. Multiple flows
   still show ECMP. Replies that never join an observed edge are omitted from the
   graph but remain in the method's semi-raw log. A failed trace simply ends at
   its last hop.
4. **enrich** — `enrich.py` resolves every hop to its origin AS, fetches each
   AS's PeeringDB facilities/IXPs, and annotates every inter-AS link with a
   `handoff`: shared facilities/IXPs, whether the outgoing AS advertises the
   destination (RouteViews), plus peering evidence. For each inter-AS edge it
   checks whether the two ASes appear contiguous in an observed AS path toward
   the destination (RouteViews, RIPE RIS, and bgproutes.io vantage points) and
   whether the two hop IPs are geographically consistent. A link is marked as a
   **confirmed peering** (green) when adjacency and geography both agree; the
   details (sources, AS paths, countries, distance) show when clicking the link.
   The AS-path evidence reuses the same adapters/parsers/cache as `aranya <IP>`
   via `source/topology.py`.

## Usage

```sh
.venv/bin/python -m paths --db paths.db trace 41.222.2.1          # all tools -> 41.222.2.1.html
.venv/bin/python -m paths --db paths.db trace 41.222.2.1 --tools mtr,traceroute
.venv/bin/python -m paths --db paths.db trace 41.222.2.1 --text   # text summary, no HTML
.venv/bin/python -m paths --db paths.db ingest mtr.json --tool mtr --target 41.222.2.1
.venv/bin/python -m paths --db paths.db show
.venv/bin/python -m paths --db paths.db html --target 41.222.2.1 -o paths.html
.venv/bin/python -m paths --db paths.db clear   # empty the paths database
.venv/bin/python -m paths --db paths.db clear 41.222.2.1  # remove one target

aranya path 41.222.2.1                       # same as `trace`, via the aranya CLI
aranya path 41.222.2.1 --tools scamper,dublin -o paths.html
aranya path --clear                           # empty the path database
aranya path --clear 41.222.2.1                # remove just that target
```

`trace` (and `aranya path`) render HTML by default; `--text` prints the per-run
text summary instead. Click a method name in the HTML to show its stored
semi-raw hop log on the right; click a hop for details, or a link for its handoff.
`html --target` picks the latest run per tool for that target; passing explicit
run ids stacks those in order. `networkx` is required for graph building;
`--no-enrich` skips the source-analysis queries.

Source-analysis queries are disk-cached (`PATHS_CACHE`, default
`~/.cache/aranya/paths`; `PATHS_CACHE_TTL`; `--no-cache` to bypass).

Tools probe differently: `mtr` uses ICMP echo, while scamper, dublin, voyage and
traceroute default to UDP here. One can reach a target that another's probe type
is filtered from; the per-tool graphs are deliberately not merged.
