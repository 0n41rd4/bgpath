#!/usr/bin/env bash
#
# Install maintained path-measurement tools and grant them raw-socket
# capabilities so they run unprivileged. Ubuntu/Debian.
#
# Maintained:  mtr, traceroute, hping3, nping(nmap), dublin-traceroute, scamper,
#              voyage (Rust Paris successor).
# Skipped:     tracebox (unmaintained since 2018) and CAIDA paris-traceroute
#              (unmaintained; scamper/voyage replace it).
#
# Usage:  sudo scripts/install-probes.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

echo "== packaged, maintained tools =="
apt-get update
apt-get install -y \
  mtr traceroute hping3 nmap dublin-traceroute \
  python3-scapy \
  libcap2-bin \
  curl ca-certificates git build-essential autoconf automake libtool pkg-config libpcap-dev

echo "== scamper: build latest from CAIDA (apt ships 2021) =="
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
listing="$(curl -fsSL https://www.caida.org/catalog/software/scamper/code/ || true)"
tarball="$(printf '%s\n' "$listing" | grep -oE 'scamper-cvs-[0-9]+\.tar\.gz' | sort -u | tail -1)"
if [ -n "$tarball" ]; then
  curl -fsSL -o "$tmp/$tarball" "https://www.caida.org/catalog/software/scamper/code/$tarball"
  tar -xzf "$tmp/$tarball" -C "$tmp"
  ( cd "$tmp/$(basename "$tarball" .tar.gz)" && ./configure && make -j"$(nproc)" && make install )
else
  echo "could not find a scamper tarball; using the apt package instead" >&2
  apt-get install -y scamper
fi

echo "== capabilities (run unprivileged) =="
setcap cap_net_raw+ep /usr/bin/mtr-packet 2>/dev/null || true
setcap cap_net_raw+ep "$(readlink -f /usr/sbin/traceroute)" 2>/dev/null || true
setcap cap_net_raw,cap_net_admin+eip /usr/sbin/hping3 2>/dev/null || true
setcap cap_net_raw,cap_net_admin+eip /usr/bin/nping 2>/dev/null || true
setcap cap_net_raw+ep "$(command -v scamper)" 2>/dev/null || true
setcap cap_net_raw+ep /usr/bin/dublin-traceroute 2>/dev/null || true

echo "== voyage: maintained Paris successor (Rust), as \$SUDO_USER =="
if [ -n "${SUDO_USER:-}" ] && command -v sudo >/dev/null 2>&1; then
  sudo -u "$SUDO_USER" -H bash -lc 'command -v cargo >/dev/null && cargo install --git https://github.com/dioptra-io/voyage' || \
    echo "cargo/voyage install skipped (install Rust, then: cargo install --git https://github.com/dioptra-io/voyage)" >&2
  setcap cap_net_raw+ep "/home/${SUDO_USER}/.cargo/bin/voyage" 2>/dev/null || true
fi

echo "== keep mtr-packet capability across upgrades =="
printf '%s\n' 'DPkg::Post-Invoke { "setcap cap_net_raw+ep /usr/bin/mtr-packet 2>/dev/null || true"; };' \
  > /etc/apt/apt.conf.d/99-aranya-caps

echo "== done =="
for b in mtr traceroute hping3 nping scamper dublin-traceroute voyage; do
  p="$(command -v "$b" 2>/dev/null || true)"
  [ -n "$p" ] && printf '%-18s %s\n' "$b" "$(getcap "$p" 2>/dev/null || echo '-')"
done
