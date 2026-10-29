# bgpath (aranya)

Evidence layer over public internet-infrastructure data. Produces two
self-contained HTML reports: a **path** report and an **IP** report.

## Install

Requires Python 3.10+.

```sh
pipx install --editable .        # puts `aranya` on PATH (editable)
# or: pip install -e .
```

`python3 aranya.py ...` also works straight from the checkout. Tests run offline:
`python3 -m unittest discover -s tests`.

## Keys

Everything runs keyless by default. Optional sources read keys from the shell or
from the gitignored `scripts/.aranya.env` (the shell wins):

```sh
cp scripts/.aranya.env.example scripts/.aranya.env
chmod 600 scripts/.aranya.env
# fill in the keys you want
```

| Key                   | Used by                                                                    |
| --------------------- | -------------------------------------------------------------------------- |
| `BGP_API_KEY`         | bgproutes.io — extra BGP/RIB evidence in the IP and path reports           |
| `IPINFO_TOKEN`        | IPinfo geolocation                                                         |
| `SHODAN_API_KEY`      | Shodan host API (paid; keyless `internetdb` already covers the free slice) |
| `MAXMIND_LICENSE_KEY` | GeoLite2 database downloads (`aranya --update-dbs`)                        |

Geo-IP databases live under `data/` (override `MAXMIND_DB` / `MAXMIND_ASN_DB` /
`DBIP_DB`) and are refreshed with `aranya --update-dbs`.

## IP & Path report

```sh
aranya path 8.8.8.8                    # aranya lookup + traceroute -> 8.8.8.8.html
aranya path 8.8.8.8 -o path.html       # custom output path
aranya path 8.8.8.8 -v                 # per-source/tool progress on stderr
aranya path 8.8.8.8 --exclude voyage   # run without voyage
aranya path --clear                    # empty the path database
```

Pings the target, then traceroutes it with every available tool (mtr,
traceroute, scamper, dublin-traceroute, voyage — one graph each). IP claims are grouped
by importance (IP facts, BGP routes, AS, identity, latency), with per-source provenance
and embedded raw fetch bodies. Sources are ranked side by side rather than collapsed to
one answer. Traceroute hops are enriched with origin AS, prefix, geolocation, PeeringDB
facilities/IXPs, and BGP peering evidence. See `paths/README.md` for the full flow.

## IP report only

```sh
aranya 8.8.8.8                        # fetch one IP (all sources, keyless by default)
aranya --html report.html             # every stored IP -> self-contained HTML
aranya --html report.html --ips 8.8.8.8,1.1.1.1
```

## Data locations

- IP database: `~/.local/share/aranya/aranya.db` (override `--db` or `ARANYA_DB`)
- Path database: `paths.db` (override `--db`)
