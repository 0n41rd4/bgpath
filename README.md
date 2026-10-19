# aranya

Evidence layer over public internet-infrastructure data. See `../proj.txt` for
the full brief.

## Status

Phase 1 (fetch + raw store + observations), phase 2 (comparison + HTML report),
phase 3 (more sources), phase 4 (entity normalization) and phase 5 (cross-IP
analysis) are implemented. 20 always-on sources + 2 PeeringDB sub-resource lookups
(facility coordinates, IX peering-LAN prefix; contextual) + 5 optional query an IP in
dependency waves; raw responses land in the `fetches` table, normalized claims
in the `observations` table.

## Usage

```sh
pipx install --editable .                      # puts `aranya` on PATH (editable)
aranya 8.8.8.8 [--db FILE]                     # fetch all sources, print observations
aranya 8.8.8.8 --dump                          # per-source raw output; dumps/last -> latest timestamp
aranya 8.8.8.8 -v                              # per-source progress on stderr
aranya --ips 8.8.8.8,1.1.1.1 --dump            # one timestamp folder, one subfolder per IP
aranya --update-dbs                            # refresh the MaxMind/DB-IP .mmdb files
python3 -m unittest discover -s tests          # 122 tests, fully offline
```

`python3 aranya.py ...` still works from the checkout.

## Views

Disagreement is the signal, not an error: the views keep every source's claim
side by side and rank them rather than collapsing to one answer.

```sh
python3 aranya.py 8.8.8.8 --view               # per-IP claims (no fetch)
python3 aranya.py 8.8.8.8 --view --normalize   # compare canonical values
python3 aranya.py 8.8.8.8 --entities           # resolved ownership entity + aliases
python3 aranya.py --report                     # cross-IP overview + agreement profile
python3 aranya.py --report --normalize         # ... over canonical values
python3 aranya.py --stats                      # cross-IP analysis (contested claims, anycast, sources)
python3 aranya.py --stats 8.8.8.8              # analysis scoped to one IP
```

`--view` prints one block per `topic.key`, coloured by claim: the consensus
value first, then dissenters, then any source that reports a *set* (marked `*`):

```
location.claim                [!] disagree   5 source(s)
    ● 37.751,-97.822                     maxmind.geolite2, ripestat.geoloc
    ◆ Mountain View, US                  dbip.lite, ipinfo
    ~ ipmap*                             30 values: Amsterdam, Netherlands, …

ownership.name                [!] disagree   2 source(s)
    ● GOGL                               rdap
    ◆ Google LLC                         peeringdb.net
```

`--report` shows, for every IP in the DB, the verdict per claim, plus a
per-source track record against each cell's consensus:

```
overview:  per-IP agreement per claim

           own.asn own.nam loc.clm idn.hst ...
     8.8.8.8    .       #       #       .
     1.1.1.1    .       #       #       #

legend: . agree  + spread  # disagree   · absent

source profile:  agreement with each cell's consensus

source                   cells  agree  dissent  multi
rdap                        17     17        0      0
ipinfo                      13      9        4      0
ripestat.geoloc              4      4        0      0
```

Colour is auto-detected; disable with `--no-color` or `NO_COLOR`.

Internals: `registry/` holds the adapters (`sources.py`), decoders (`parsers.py`,
`ripe.py`), the parse step (`observe.py`) and the raw/observation store
(`store.py`). `views.py` holds read-only projections over the existing tables,
`aggregate.py` turns those rows into labelled claims / consensus / profiles, and
`render.py` draws them. Nothing here writes to the store.

## Entity normalization

`entities.py` canonicalises values without touching the raw store: ASN to int
(`AS15169` → `15169`), country to ISO-2, prefix to CIDR, range normalised, org
names stripped of `AS<n>` prefixes and legal suffixes. `--normalize` applies
this to any view (`--view`, `--report`, `--stats`), so formatting-only
disagreements vanish; values it cannot parse are kept verbatim, never merged.

`entities.resolve()` anchors name aliases to the ASN the same source reports,
then folds in unlinked names whose canonical form matches a known entity — so
`"AS15169 Google LLC"`, `"GOOGLE - Google LLC"` and PeeringDB's `"Google LLC"`
all resolve to `AS15169`, while RIR's `"GOGL"` stays separate.

## Cross-IP analysis

`analyze.py` reduces the whole store to patterns (`--stats`): verdict
distribution, per-claim contested rate, anycast-like sources (one source
enriching many location claims), and per-source conformity.

## HTML report

`export.py` renders the same aggregate data as a **self-contained, offline HTML
file** (no server, no CDN, no build step):

```sh
python3 aranya.py --html report.html --with-observations
python3 aranya.py --export data.json --ips 8.8.8.8,1.1.1.1 --topics location,ownership
python3 aranya.py --show-fetch 42                 # print a stored raw body
```

Open `report.html` in a browser. Tabs: claims, source values, overview,
agreement profile, geo. Cells carry the actual value (not just a verdict), so
"agreeing on what" reads directly off the table; the geo tab uses a coarse
Natural Earth 110m outline (embedded in `world.txt`). Filter state lives in the
URL hash, so views are shareable. If `--with-observations` is omitted,
drill-down still works but only lists provenance and the `--show-fetch ID`
command to pull the raw body.

Design rules the report follows:

- **Verdicts count independent upstreams, not sources.** A claim shows both
  `N src / M up`, and `agree`/`disagree` are computed over distinct `upstream`
  groups (MaxMind City + ASN collapse to one upstream). Unknowns stay distinct.
- **Failure is not disagreement.** Cell states are `agree`, `dissent`, `multi`,
  `single`, `no_data`, `error`, `skipped`, `absent` — an outage never looks quiet.
- **Single is not agreement.** One upstream alone gets its own state.
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
| `routeviews.prefix` | RouteViews collectors (U of Oregon + 9 IXes) + Routinator/rpki-client | observed-passive |
| `cymru.origin` | Team Cymru BGP (via DNS) | observed-passive |
| `irr.origin` | RADb / IRR route objects (registered intent) | reported |
| `rdap` | RIR RDAP | reported |
| `peeringdb.net`, `peeringdb.netfac`, `peeringdb.netixlan` | PeeringDB directory | reported |
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

## Optional sources

These sources need credentials or a local database file; without them they are
reported as `skipped (...)`. Credentials come from the shell or from the
gitignored `scripts/.aranya.env` (copy `scripts/.aranya.env.example`); the shell
wins. The `.mmdb` paths default to `data/` and can be overridden.

| Source | Env var | Setup |
|---|---|---|
| IPinfo | `IPINFO_TOKEN` | free token at ipinfo.io; can live in `scripts/.aranya.env` |
| Shodan host API | `SHODAN_API_KEY` | account at shodan.io; **the host API consumes query credits (paid)** — keyless `internetdb` already covers the free slice |
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
