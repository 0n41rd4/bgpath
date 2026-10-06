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
python3 -m unittest discover -s tests          # 30 tests, fully offline
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
