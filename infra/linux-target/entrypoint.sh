#!/usr/bin/env bash
set -euo pipefail

MANAGER_HOST="${WAZUH_MANAGER:-wazuh.manager}"
AGENT_NAME="${WAZUH_AGENT_NAME:-linux-target}"

# Initialize nftables filter table/chain so LinuxFirewallAdapter can insert/delete rules immediately.
nft add table inet filter || true
nft add chain inet filter input '{ type filter hook input priority 0 ; policy accept ; }' || true

# Ensure log files exist before daemons and Wazuh agent open them.
touch /var/log/auth.log /var/log/nginx/access.log /var/log/nginx/error.log /var/log/suricata/eve.json
chmod 644 /var/log/auth.log /var/log/suricata/eve.json

# Start OpenSSH logging directly to /var/log/auth.log (containers run without systemd/rsyslog).
/usr/sbin/sshd -E /var/log/auth.log

# Start Nginx Web Server.
nginx

# Start Suricata NIDS inspecting container eth0 (disable checksum validation on veth).
IFACE="${SURICATA_INTERFACE:-eth0}"
rm -f /var/run/suricata.pid
suricata -i "$IFACE" -k none -S /etc/suricata/rules/local.rules -l /var/log/suricata -D

# Configure Wazuh Agent to point to the Wazuh Manager container.
sed "s/__WAZUH_MANAGER__/${MANAGER_HOST}/g" /opt/soclab/ossec.conf.tmpl > /var/ossec/etc/ossec.conf

# Register agent on first boot (or retry briefly while manager boots).
if [ ! -s /var/ossec/etc/client.keys ]; then
  for attempt in $(seq 1 15); do
    if /var/ossec/bin/agent-auth -m "$MANAGER_HOST" -A "$AGENT_NAME"; then
      break
    fi
    echo "Waiting for Wazuh manager enrollment ($attempt/15)..."
    sleep 3
  done
fi

/var/ossec/bin/wazuh-control start

trap '/var/ossec/bin/wazuh-control stop || true; nginx -s stop || true; exit 0' SIGTERM SIGINT

# Keep container alive streaming key logs.
tail -n 20 -F /var/log/suricata/eve.json /var/log/auth.log /var/ossec/logs/ossec.log
