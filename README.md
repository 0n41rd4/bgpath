# aranya

Evidence layer over public internet-infrastructure data. See `../proj.txt` for
the full brief.

## Status

Phase 1 (fetch + raw store + observations), phase 2 (comparison + HTML report),
phase 3 (more sources), phase 4 (entity normalization) and phase 5 (cross-IP
analysis) are implemented. 21 always-on sources + PeeringDB facility/IX follow-ups +
5 optional query an IP in dependency waves; raw responses land in the `fetches`
table, normalized claims in the `observations` table.

## Usage

```sh
pipx install --editable .                      # puts `aranya` on PATH (editable)
aranya 8.8.8.8 [--db FILE]                     # fetch all sources, print observations
aranya 8.8.8.8 --dump                          # per-source raw output; dumps/last -> latest timestamp
aranya 8.8.8.8 -v                              # per-source progress on stderr
aranya --ips 8.8.8.8,1.1.1.1 --dump            # one timestamp folder, one subfolder per IP
aranya path 8.8.8.8                            # ping + traceroute (all tools) -> HTML report
aranya path --clear                            # empty the path database
aranya path --clear 8.8.8.8                    # remove just that target's path runs
aranya --update-dbs                            # refresh the MaxMind/DB-IP .mmdb files
aranya --clear                                 # empty the whole database and exit
aranya --clear 8.8.8.8                         # empty just that IP and exit
python3 -m unittest discover -s tests          # 107 tests, fully offline
```

Each dump source folder contains `output.txt` (raw body), `raw_output.json`
(the body as JSON; non-JSON bodies are wrapped as `{"raw": ...}`), and
`output.json` (status, URL, parsed payload). AS-scoped sources live under
`AS<asn>/`; PeeringDB facility and IX details are fetched in bulk and stored
under `AS<asn>/peeringdb.fac/` and `AS<asn>/peeringdb.ixpfx/`.

Re-running an IP replaces that source's observations, so views do not accumulate
duplicates; `fetches` are kept as raw history. `--clear` and `--clear-ip` remove
both.

The database defaults to `~/.local/share/aranya/aranya.db`
(`$XDG_DATA_HOME/aranya/aranya.db`), independent of the working directory.
Override with `--db` or `ARANYA_DB`. An older `./aranya.db` is not picked up
automatically; pass `--db ./aranya.db` or move it into place.

`python3 aranya.py ...` still works from the checkout.

## Report

Disagreement is the signal, not an error: the report keeps every source's claim
side by side and ranks them rather than collapsing to one answer.

```sh
python3 aranya.py 8.8.8.8 --report     # facts + contested claims for one IP (no fetch)
python3 aranya.py --report             # all stored IPs in one comparison table
python3 aranya.py --report --ips 8.8.8.8,1.1.1.1
python3 aranya.py 8.8.8.8 --entities   # ownership entity + aliases
```

One IP:

```
8.8.8.8
  ASN          AS15169
  AS Network   Google LLC
  Prefix       8.8.8.0/24
  Country      US
  Location     San Jose, US
  Hostname     dns.google
  RPKI         valid
  AS PeeringDB net 433 · Content
  AS footprint 135 facilities · 175 IXPs (PeeringDB)

  anycast-like: ipmap reports 29 location values

  contested (3):
    ! Hostname       dns.google (rdns.ptr) | internetdb*: 2 values: cas.emarketer.com, dns.google
    ! Location       37.751,-97.822 (ip.guide, ripestat.geoloc) | San Jose, US (ipwho.is) | ipmap*: 29 values: ...
    ! AS Network name Google LLC (ip.guide, peeringdb.net) | GOGL (rdap) | Google (irr.origin)
```

Several IPs:

```
ip               asn       country  as network                location                  hostname                      contested
8.8.8.8          AS15169   US       Google LLC                San Jose, US              dns.google                            3
1.1.1.1          AS13335   AU       Cloudflare, Inc.          Sydney, AU                one.one.one.one                       0

2 IP(s) · 33 claims · 3 contested
most contested: AS Network name (1), Hostname (1), Location (1)
anycast-like: 8.8.8.8 · ipmap reports 29 location values
```

Values are labelled by source; `source*` means that source reported a set. The
report is read-only: fetch first with `aranya <IP>`.

Internals: `registry/` holds the adapters (`sources.py`), decoders (`parsers.py`,
`ripe.py`), the parse step (`observe.py`) and the raw/observation store
(`store.py`). `views.py` holds read-only projections, `aggregate.py` turns rows
into claims/consensus, and `render.py` draws the report and its anycast summary. Nothing here writes to the store.

## Entity resolution

`entities.py` normalizes values without touching the raw store: ASN to int
(`AS15169` → `15169`), country to ISO-2, prefix to CIDR, range normalized, org
names stripped of legal suffixes. `entities.resolve()` anchors name aliases to
the ASN the same source reports, then folds in unlinked names whose canonical
form matches a known entity — so `"AS15169 Google LLC"`, `"GOOGLE - Google LLC"`
and PeeringDB's `"Google LLC"` all resolve to `AS15169`, while RIR's `"GOGL"`
stays separate.

## HTML report

`export.py` renders the same aggregate data as a **self-contained, offline HTML
file** (no server, no CDN, no build step):

```sh
python3 aranya.py --html report.html          # all stored IPs; observations + raw sources embedded
python3 aranya.py --export data.json --ips 8.8.8.8,1.1.1.1 --topics location,ownership
python3 aranya.py --export data.json --with-observations
python3 aranya.py --show-fetch 42                 # print a stored raw body
```

Open `report.html` in a browser. Omit `--ips` to include every stored IP; the
IP selector lists them all. Tabs: claims, source values, overview, agreement
profile, geo. Cells carry the actual value (not just a verdict), so
"agreeing on what" reads directly off the table; the geo tab uses a coarse
Natural Earth 110m outline (embedded in `world.txt`). Filter state lives in the
URL hash, so views are shareable. Claims are grouped by importance — IP facts,
BGP routes, AS, identity, latency — instead of alphabetically. The provenance drawer groups the embedded
observations by source and shows each value. Each source also expands to the
`GET` API endpoints and raw fetch bodies used by those observations. Because raw
bodies are embedded, HTML reports can be large.

Design rules the report follows:

- **Verdicts count independent upstreams, not sources.** A claim shows both
  `N src / M up`, and `agree`/`disagree` are computed over distinct `upstream`
  groups (MaxMind City + ASN collapse to one upstream). Unknowns stay distinct.
- **Failure is not disagreement.** Cell states are `agree`, `dissent`, `multi`,
  `single`, `no_data`, `error`, `skipped`, `absent` — an outage never looks quiet.
- **Single is not agreement.** One upstream alone gets its own state.
- **A set is not a conflict.** Several values from one upstream are `set`
  (`spread` internally); independent upstreams returning different values are
  `disagree`.
- **Latency is per probe.** Different probes measure different paths, so the
  latency claim shows a probe count and RTT range, not a consensus location.
- **The agreement profile measures conformity, not accuracy** — it is a
  diversity signal, not a trust ranking.
- **All values are hostile.** The UI only ever sets `textContent`, and the
  embedded JSON escapes `<`, `>`, `&` (so a PTR name like `<img onerror=…>`
  cannot execute). A test fixture covers this.
- **Deterministic.** No timestamps in the contract except `latest_observation`,
  derived from the data; everything is sorted; `schema_version` is present.



## Sources

Always-on, no account or key. Grouped by backend so independent vantage points
stay visible — the same question answered from different infrastructure is what
makes a disagreement meaningful:

| Source | Backend / vantage | Evidence |
|---|---|---|
| `ripestat.network-info`, `ripestat.as-overview`, `ripestat.asn-neighbours` | RIPE NCC (RIS BGP) | observed-passive |
| `ripestat.geoloc` | RIPE NCC (embeds MaxMind/IP2Location) | reported |
| `ipmap` | RIPE NCC (Atlas latency engine + rDNS) | inferred |
| `routeviews.prefix` | RouteViews API collectors (IXP + U of Oregon) + Routinator/rpki-client | observed-passive |
| `ris.looking-glass` | RIPE NCC RIS Remote Route Collectors (RRCs) | observed-passive |
| `bgp.tools` | bgp.tools' own route collector sessions (free whois interface) | observed-passive |
| `cymru.origin` | Team Cymru BGP (via DNS) | observed-passive |
| `irr.origin` | RADb / IRR route objects (registered intent) | reported |
| `rdap` | RIR RDAP | reported |
| `peeringdb.net`, `peeringdb.netfac`, `peeringdb.netixlan`, `peeringdb.fac`, `peeringdb.ixpfx` | PeeringDB directory (bulk facility/IX lookups follow the net) | reported |
| `ip.guide` | ip.guide | reported |
| `ipwho.is` | ipwho.is | reported |
| `rdns.ptr` | DNS PTR | reported |
| `internetdb` | Shodan (keyless slice) | observed-passive |
| `crtsh` | Certificate Transparency logs | reported |
| `globalping.ping` | Globalping community probes | observed-active |
| `atlas.ping` | RIPE Atlas probes | observed-active |
| `atlas.probes` | RIPE Atlas probe locations in an AS (by country) | observed-passive |

## Deferred sources

Independent backends worth adding later, deliberately not wired yet (none is a
re-front of data we already collect):

| Source | Backend / vantage | Setup | Why deferred |
|---|---|---|---|
| Cloudflare Radar | Cloudflare's own global network (BGP + traffic analytics) | free API token (`CLOUDFLARE_RADAR_TOKEN`) | independent vantage, but key-gated |
| GreyNoise | GreyNoise's own sensor network | community API key (`GREYNOISE_API_KEY`) | distinct sensor set, but a security/reputation data class |
| Censys | Censys' own scanning network | API ID + secret (`CENSYS_API_ID`/`CENSYS_API_SECRET`) | distinct scanner set; same class as Shodan |
| PCH Looking Glass | Packet Clearing House route collectors | none | public web form only; PCH explicitly asks that it not be scraped |
| Isolario | Isolario route collectors | none | no stable public API documented |

## Optional sources

These sources need credentials or a local database file; without them they are
reported as `skipped (...)`. Credentials come from the shell or from the
gitignored `scripts/.aranya.env` (copy `scripts/.aranya.env.example`); the shell
wins. The `.mmdb` paths default to `data/` and can be overridden.

| Source | Env var | Setup |
|---|---|---|
| IPinfo | `IPINFO_TOKEN` | free token at ipinfo.io; can live in `scripts/.aranya.env` |
| Shodan host API | `SHODAN_API_KEY` | account at shodan.io; **the host API consumes query credits (paid)** — keyless `internetdb` already covers the free slice |
| bgproutes.io | `BGP_API_KEY` | free API key at bgproutes.io; queries its own BGP/BMP vantage points |
| BGP.Tools HTTP API | paid | free whois/table exports are used; the detailed HTTP API is paid and not used |
| MaxMind GeoLite2 City | `MAXMIND_DB` | defaults to `data/GeoLite2-City.mmdb` (free account at maxmind.com) + `pip install maxminddb` |
| MaxMind GeoLite2 ASN | `MAXMIND_ASN_DB` | defaults to `data/GeoLite2-ASN.mmdb` (same account) |
| DB-IP Lite | `DBIP_DB` | defaults to `data/dbip-city-lite.mmdb` (free download at db-ip.com) |

`aranya --update-dbs` (or `./scripts/update_geoip.sh`) refreshes all three
databases. Both read the MaxMind key from `scripts/.aranya.env`; DB-IP needs no
key.

Tokens/keys are redacted in the stored `fetches.url`.

## Keeping the geolocation databases fresh

The `.mmdb` files go stale: **MaxMind GeoLite2 updates ~weekly**, **DB-IP Lite
~monthly**. Refresh them with:

```sh
aranya --update-dbs         # or ./scripts/update_geoip.sh
```

The MaxMind license key is read from the environment or from the gitignored
`scripts/.aranya.env`:

```sh
echo 'MAXMIND_LICENSE_KEY=your-key' >> scripts/.aranya.env
```

Schedule it (cron, weekly):

```cron
17 4 * * 1 cd /path/to/aranya && ./scripts/update_geoip.sh >> data/update.log 2>&1
```

or with a systemd timer:

```ini
# ~/.config/systemd/user/aranya-geoip.service
[Service]
Type=oneshot
WorkingDirectory=/path/to/aranya
EnvironmentFile=/path/to/aranya/scripts/.aranya.env
ExecStart=/path/to/aranya/scripts/update_geoip.sh
```

```ini
# ~/.config/systemd/user/aranya-geoip.timer
[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

Then `systemctl --user enable --now aranya-geoip.timer`.

## Data files

MaxMind GeoLite2 offers **City**, **ASN** and **Country** editions; DB-IP Lite
ships **City**. What aranya uses, and why:

- **City** (`MAXMIND_DB`, `DBIP_DB`) — `country` / `city` / `location` schema →
  `location` claims.
- **ASN** (`MAXMIND_ASN_DB`) — `autonomous_system_number` /
  `autonomous_system_organization` → not in City, so it adds `ownership.asn`
  and `ownership.org` claims. Its own schema, hence its own adapter
  (`maxmind.asn`).
- **Country** — *not fetched*: City already carries `country` and
  `registered_country`, so the Country edition is redundant with City.

Independence note: City, ASN and DB-IP are all geolocation/registry derivatives
and likely share inputs, so they count as roughly one upstream "vote" — they add
coverage, not independent evidence.
