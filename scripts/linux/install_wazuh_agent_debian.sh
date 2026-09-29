#!/usr/bin/env bash
set -Eeuo pipefail

# Debian/Ubuntu endpoint installer. Run as root:
#   sudo ./scripts/linux/install_wazuh_agent_debian.sh 192.168.56.10 linux-client

MANAGER="${1:-}"
AGENT_NAME="${2:-$(hostname)}"

if [ -z "$MANAGER" ]; then
  echo "Usage: sudo $0 <WAZUH_MANAGER_IP_OR_DNS> [AGENT_NAME]" >&2
  exit 2
fi

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "Run this script as root (sudo)." >&2
  exit 1
fi

apt-get update
apt-get install -y gnupg apt-transport-https curl
install -d -m 0755 /usr/share/keyrings
rm -f /usr/share/keyrings/wazuh.gpg
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 0644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update

WAZUH_MANAGER="$MANAGER" \
WAZUH_REGISTRATION_SERVER="$MANAGER" \
WAZUH_AGENT_NAME="$AGENT_NAME" \
  apt-get install -y wazuh-agent

systemctl daemon-reload
systemctl enable --now wazuh-agent

# Prevent accidental agent upgrades beyond the manager version in this lab.
echo "wazuh-agent hold" | dpkg --set-selections

echo "Wazuh agent installed and started: $AGENT_NAME -> $MANAGER"
systemctl --no-pager --full status wazuh-agent || true
