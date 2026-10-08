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
python3 -m unittest discover -s tests          # 34 tests, fully offline
```

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
