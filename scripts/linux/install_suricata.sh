#!/usr/bin/env bash
set -euo pipefail

INTERFACE="${1:-}"
EVE_PATH="/var/log/suricata/eve.json"
SURICATA_YAML="/etc/suricata/suricata.yaml"
SURICATA_DEFAULTS="/etc/default/suricata"
MARKER="# SOC-LAB-EVE-BLOCK"

if [[ -z "$INTERFACE" ]]; then
  echo "Usage: sudo $0 <network-interface>" >&2
  echo >&2
  echo "Available interfaces:" >&2
  ip -o link show | awk -F': ' '{print " - " $2}' >&2
  exit 2
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run this script as root (sudo)." >&2
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  echo "Could not detect OS. /etc/os-release is missing." >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
DISTRO_FAMILY="${ID:-} ${ID_LIKE:-}"
if ! grep -Eqi 'debian|ubuntu' <<<"$DISTRO_FAMILY"; then
  echo "Unsupported distribution: ${PRETTY_NAME:-unknown}. This installer supports Debian/Ubuntu." >&2
  exit 1
fi

if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
  echo "Network interface not found: $INTERFACE" >&2
  echo "Use 'ip link' to list valid interfaces." >&2
  exit 1
fi

echo "Installing Suricata package..."
apt-get update
apt-get install -y suricata

if [[ -f "$SURICATA_DEFAULTS" ]]; then
  cp --update=none "$SURICATA_DEFAULTS" "$SURICATA_DEFAULTS.bak" || true
  if grep -Eq '^IFACE=' "$SURICATA_DEFAULTS"; then
    sed -i "s|^IFACE=.*$|IFACE=\"$INTERFACE\"|" "$SURICATA_DEFAULTS"
  else
    printf '\nIFACE="%s"\n' "$INTERFACE" >>"$SURICATA_DEFAULTS"
  fi
fi

if [[ -f "$SURICATA_YAML" ]]; then
  cp --update=none "$SURICATA_YAML" "$SURICATA_YAML.bak" || true

  # Update the first active af-packet interface to the selected NIC.
  tmp_yaml="$(mktemp)"
  awk -v iface="$INTERFACE" '
    /^af-packet:[[:space:]]*$/ { in_af=1; print; next }
    in_af == 1 && $0 ~ /^[^[:space:]#]/ { in_af=0 }
    in_af == 1 && updated == 0 && $0 ~ /^[[:space:]]*-[[:space:]]*interface:[[:space:]]*/ {
      sub(/interface:[[:space:]]*.*/, "interface: " iface)
      updated=1
      print
      next
    }
    { print }
  ' "$SURICATA_YAML" >"$tmp_yaml"
  mv "$tmp_yaml" "$SURICATA_YAML"

  if grep -q "eve.json" "$SURICATA_YAML"; then
    echo "suricata.yaml already references eve.json; no changes needed."
  elif grep -q "$MARKER" "$SURICATA_YAML"; then
    echo "SOC Lab EVE block already present; no changes needed."
  else
    cat >>"$SURICATA_YAML" <<EOF

$MARKER
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
EOF
    echo "Added minimal EVE output block to suricata.yaml."
  fi
fi

install -d -m 0755 /var/log/suricata
if [[ ! -f "$EVE_PATH" ]]; then
  touch "$EVE_PATH"
fi

systemctl daemon-reload
systemctl enable suricata
if ! systemctl restart suricata; then
  echo "Suricata failed to start. Diagnostic output:" >&2
  systemctl --no-pager --full status suricata || true
  journalctl -xeu suricata --no-pager -n 60 || true
  exit 1
fi

echo
echo "Suricata service status:"
systemctl --no-pager --full status suricata || true

echo
echo "Suricata interface ............ $INTERFACE"
echo "Suricata config ............... $SURICATA_YAML"
echo "EVE JSON path ................. $EVE_PATH"
echo "Use: tail -f $EVE_PATH"
