# aranya

Evidence layer over public internet-infrastructure data. See `../proj.txt` for
the full brief.

## Status

Phase 1 (fetch layer + raw store + observations). 14 always-on sources query an
IP in dependency waves; raw responses land in the `fetches` table, normalized
claims in the `observations` table.

## Usage

```sh
python3 aranya.py 8.8.8.8 [--db FILE]          # fetch all sources, print observations
python3 -m unittest discover -s tests          # 45 tests, fully offline
```

## Views

Disagreement is the signal, not an error: the views keep every source's claim
side by side and rank them rather than collapsing to one answer.

```sh
python3 aranya.py 8.8.8.8 --view               # per-IP claims (no fetch)
python3 aranya.py --report                     # cross-IP overview + source profile
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

Internals: `views.py` holds read-only projections over the existing tables,
`aggregate.py` turns those rows into labelled claims / consensus / profiles, and
`render.py` draws them. Nothing here writes to the store.

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



## Optional sources

These sources need credentials or a local database file; without them they are
reported as `skipped (...)`:

| Source | Env var | Setup |
|---|---|---|
| IPinfo | `IPINFO_TOKEN` | free token at ipinfo.io |
| Shodan host API | `SHODAN_API_KEY` | account at shodan.io; **the host API consumes query credits (paid)** — keyless `internetdb` already covers the free slice |
| MaxMind GeoLite2 City | `MAXMIND_DB` | path to GeoLite2-City `.mmdb` (free account at maxmind.com) + `pip install maxminddb` |
| MaxMind GeoLite2 ASN | `MAXMIND_ASN_DB` | path to GeoLite2-ASN `.mmdb` (same account) |
| DB-IP Lite | `DBIP_DB` | path to DB-IP Lite City `.mmdb` (free download at db-ip.com) |

Tokens/keys are redacted in the stored `fetches.url`.

## Keeping the geolocation databases fresh

The `.mmdb` files go stale: **MaxMind GeoLite2 updates ~weekly**, **DB-IP Lite
~monthly**. Refresh them with:

```sh
./scripts/update_geoip.sh   # writes data/dbip-city-lite.mmdb, data/GeoLite2-City.mmdb, data/GeoLite2-ASN.mmdb
```

The MaxMind license key is read from the environment or from the gitignored
`scripts/.geoip.env`:

```sh
echo 'export MAXMIND_LICENSE_KEY=your-key' > scripts/.geoip.env
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
EnvironmentFile=/path/to/aranya/scripts/.geoip.env
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
