#!/usr/bin/env bash
# Refresh the local geolocation databases that aranya reads via MAXMIND_DB / DBIP_DB.
# Cron/systemd-safe. Never prints secrets.
#
# DB-IP Lite  (City): free, published monthly, no account.
# MaxMind GeoLite2 (City): free, published weekly, needs MAXMIND_LICENSE_KEY
#   (from a free account). Read from the environment, or from a gitignored
#   scripts/.geoip.env file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${ARANYA_DATA:-$SCRIPT_DIR/../data}"
mkdir -p "$DATA_DIR"

if [[ -f "$SCRIPT_DIR/.geoip.env" ]]; then
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/.geoip.env"
fi

# --- DB-IP Lite City: try this month, fall back to last month ---
for offset in 0 -1; do
  ym=$(date -d "$offset month" +%Y-%m)
  url="https://download.db-ip.com/free/dbip-city-lite-${ym}.mmdb.gz"
  tmpgz="$DATA_DIR/.dbip.mmdb.gz"
  if curl -fsSL "$url" -o "$tmpgz"; then
    gunzip -f "$tmpgz"
    mv "${tmpgz%.gz}" "$DATA_DIR/dbip-city-lite.mmdb"
    echo "DB-IP Lite: updated from $ym"
    break
  fi
done

# --- MaxMind GeoLite2-City: weekly, needs the license key ---
if [[ -n "${MAXMIND_LICENSE_KEY:-}" ]]; then
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  curl -fsSL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" -o "$tmpdir/geoip.tar.gz"
  tar -xzf "$tmpdir/geoip.tar.gz" -C "$tmpdir"
  find "$tmpdir" -name '*.mmdb' -exec cp {} "$DATA_DIR/GeoLite2-City.mmdb" \;
  echo "MaxMind GeoLite2-City: updated"
else
  echo "MaxMind: MAXMIND_LICENSE_KEY not set, skipped" >&2
fi

ls -l "$DATA_DIR"/*.mmdb
