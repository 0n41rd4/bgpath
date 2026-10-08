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

Four sources need credentials or a local database file; without them they are
reported as `skipped (...)`:

| Source | Env var | Setup |
|---|---|---|
| IPinfo | `IPINFO_TOKEN` | free token at ipinfo.io |
| Shodan host API | `SHODAN_API_KEY` | account at shodan.io; **the host API consumes query credits (paid)** — keyless `internetdb` already covers the free slice |
| MaxMind GeoLite2 | `MAXMIND_DB` | path to GeoLite2-City `.mmdb` (free account at maxmind.com) + `pip install maxminddb` |
| DB-IP Lite | `DBIP_DB` | path to DB-IP Lite `.mmdb` (free download at db-ip.com) + `pip install maxminddb` |

Tokens/keys are redacted in the stored `fetches.url`.

## Keeping the geolocation databases fresh

The `.mmdb` files go stale: **MaxMind GeoLite2 updates ~weekly**, **DB-IP Lite
~monthly**. Refresh them with:

```sh
./scripts/update_geoip.sh              # writes data/dbip-city-lite.mmdb and data/GeoLite2-City.mmdb
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

DB-IP Lite ships **City**; MaxMind GeoLite2 also offers **ASN** and **Country**
editions. The current `maxmind.geolite2` / `dbip.lite` adapters expect the City
schema (`country`/`city`/`location`), so City is what to fetch. ASN/Country
editions use a different schema and would need their own adapters.
