#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${1:-}"
EVE_PATH="${2:-/var/log/suricata/eve.json}"
RESTART_MODE="${3:-}"
CHANGED=0
BACKUP_PATH=""
SKIP_RESTART=0

if [[ "$RESTART_MODE" == "--no-restart" ]]; then
  SKIP_RESTART=1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run this script as root (sudo)." >&2
  exit 1
fi

if [[ -z "$CONFIG_PATH" ]]; then
  for candidate in \
    /var/ossec/etc/ossec.conf \
    /opt/ossec/etc/ossec.conf \
    /Library/Ossec/etc/ossec.conf; do
    if [[ -f "$candidate" ]]; then
      CONFIG_PATH="$candidate"
      break
    fi
  done
fi

if [[ -z "$CONFIG_PATH" || ! -f "$CONFIG_PATH" ]]; then
  echo "Could not find Wazuh agent configuration file (ossec.conf)." >&2
  echo "Usage: sudo $0 [/path/to/ossec.conf] [/var/log/suricata/eve.json] [--no-restart]" >&2
  exit 1
fi

echo "Using ossec.conf: $CONFIG_PATH"
echo "Target EVE path: $EVE_PATH"

ensure_ossec_conf_permissions() {
  local ossec_etc_dir
  local ossec_root_dir
  local read_user

  ossec_etc_dir="$(dirname "$CONFIG_PATH")"
  ossec_root_dir="$(dirname "$ossec_etc_dir")"
  read_user="${SOCLAB_OSSEC_READ_USER:-${SUDO_USER:-}}"

  chown root:wazuh "$CONFIG_PATH" || true
  chmod 640 "$CONFIG_PATH" || true

  if command -v setfacl >/dev/null 2>&1 && [[ -n "$read_user" ]]; then
    setfacl -m "u:${read_user}:rx" "$ossec_root_dir" "$ossec_etc_dir" || true
    setfacl -m "u:${read_user}:r" "$CONFIG_PATH" || true
    echo "Applied ACL read access for user: $read_user"
  fi
}

HAS_LOCATION=0
HAS_JSON=0
if grep -Fq "<location>$EVE_PATH</location>" "$CONFIG_PATH"; then
  HAS_LOCATION=1
fi
if grep -Fq "<log_format>json</log_format>" "$CONFIG_PATH"; then
  HAS_JSON=1
fi

if [[ "$HAS_LOCATION" -eq 1 && "$HAS_JSON" -eq 1 ]]; then
  echo "Suricata localfile block already present. No changes required."
else
  BACKUP_PATH="$CONFIG_PATH.bak.$(date +%Y%m%d%H%M%S)"
  cp "$CONFIG_PATH" "$BACKUP_PATH"

  TMP_FILE="$(mktemp)"
  if ! awk -v eve_path="$EVE_PATH" '
    { lines[NR] = $0 }
    END {
      close_idx = 0
      for (i = NR; i >= 1; i--) {
        if (lines[i] ~ /<\/ossec_config>/) {
          close_idx = i
          break
        }
      }

      if (close_idx == 0) {
        for (i = 1; i <= NR; i++) {
          print lines[i]
        }
        exit 2
      }

      for (i = 1; i < close_idx; i++) {
        print lines[i]
      }

      print "  <localfile>"
      print "    <log_format>json</log_format>"
      print "    <location>" eve_path "</location>"
      print "  </localfile>"

      for (i = close_idx; i <= NR; i++) {
        print lines[i]
      }
    }
  ' "$CONFIG_PATH" >"$TMP_FILE"; then
    rm -f "$TMP_FILE"
    echo "Could not find </ossec_config> in ossec.conf." >&2
    if [[ -n "$BACKUP_PATH" && -f "$BACKUP_PATH" ]]; then
      cp "$BACKUP_PATH" "$CONFIG_PATH"
      ensure_ossec_conf_permissions
      echo "Restored backup: $BACKUP_PATH" >&2
    fi
    exit 1
  fi

  mv "$TMP_FILE" "$CONFIG_PATH"
  ensure_ossec_conf_permissions
  CHANGED=1
  echo "Inserted Suricata EVE localfile block."
fi

validate_xml() {
  python3 - "$CONFIG_PATH" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    text = handle.read()

# Wazuh/ossec.conf can include multiple <ossec_config> blocks.
# Wrap the file in a synthetic root so standard XML parsers can validate it.
text = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", text, count=1, flags=re.IGNORECASE)
wrapped = f"<wazuh_config_wrapper>\n{text}\n</wazuh_config_wrapper>"
ET.fromstring(wrapped)
PY
}

if ! validate_xml; then
  echo "ossec.conf validation failed." >&2
  if [[ -n "$BACKUP_PATH" && -f "$BACKUP_PATH" ]]; then
    cp "$BACKUP_PATH" "$CONFIG_PATH"
    ensure_ossec_conf_permissions
    echo "Restored backup: $BACKUP_PATH" >&2
  fi
  exit 1
fi

validate_wazuh_config() {
  if [[ -x /var/ossec/bin/wazuh-agentd ]]; then
    /var/ossec/bin/wazuh-agentd -t
  else
    return 0
  fi
}

if ! validate_wazuh_config; then
  echo "Wazuh native config validation failed (wazuh-agentd -t)." >&2
  if [[ -n "$BACKUP_PATH" && -f "$BACKUP_PATH" ]]; then
    cp "$BACKUP_PATH" "$CONFIG_PATH"
    ensure_ossec_conf_permissions
    echo "Restored backup after Wazuh validation failure: $BACKUP_PATH" >&2
  fi
  if [[ -f /var/ossec/logs/ossec.log ]]; then
    echo "--- /var/ossec/logs/ossec.log (last 80 lines) ---" >&2
    tail -n 80 /var/ossec/logs/ossec.log || true
  fi
  exit 1
fi

if [[ "$CHANGED" -eq 1 ]]; then
  if [[ "$SKIP_RESTART" -eq 1 ]]; then
    echo "Skipping Wazuh agent restart (--no-restart)."
    echo
    echo "Wazuh ossec.conf ............. $CONFIG_PATH"
    echo "EVE JSON integration ......... configured"
    echo "Backup (if changed) .......... ${BACKUP_PATH:-not-created}"
    exit 0
  fi

  echo "Restarting Wazuh agent to apply changes..."
  if systemctl list-unit-files | grep -q '^wazuh-agent'; then
    if ! systemctl restart wazuh-agent; then
      echo "Wazuh agent restart failed. Collecting diagnostics..." >&2
      systemctl --no-pager --full status wazuh-agent || true
      journalctl -xeu wazuh-agent --no-pager -n 60 || true
      if [[ -f /var/ossec/logs/ossec.log ]]; then
        echo "--- /var/ossec/logs/ossec.log (last 80 lines) ---" >&2
        tail -n 80 /var/ossec/logs/ossec.log || true
      fi
      exit 1
    fi
    systemctl --no-pager --full status wazuh-agent || true
  else
    echo "wazuh-agent service not found via systemd. Restart manually if needed."
  fi
else
  echo "No restart needed (configuration unchanged)."
fi

echo
echo "Wazuh ossec.conf ............. $CONFIG_PATH"
echo "EVE JSON integration ......... configured"
echo "Backup (if changed) .......... ${BACKUP_PATH:-not-created}"
