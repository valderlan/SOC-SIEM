#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ ! -f .env ]; then
  cp .env.example .env
fi

if grep -qE '^SOCLAB_WAZUH_PASSWORD=(CHANGE_ME|\s*)$' .env; then
  sed -i 's/^SOCLAB_WAZUH_PASSWORD=.*/SOCLAB_WAZUH_PASSWORD=MyS3cr37P450r.*-/' .env
fi
if grep -qE '^SOCLAB_WEBHOOK_TOKEN=(CHANGE_ME|\s*)$' .env; then
  sed -i 's/^SOCLAB_WEBHOOK_TOKEN=.*/SOCLAB_WEBHOOK_TOKEN=soclab-dev-token/' .env
fi

if [ -d infra/wazuh-docker ] && [ ! -f infra/wazuh-docker/single-node/docker-compose.yml ]; then
  rm -rf infra/wazuh-docker
fi

./scripts/bootstrap_wazuh.sh infra/wazuh-docker

mkdir -p runtime/suricata runtime/shuffle-apps runtime/shuffle-files logs/evidence
docker compose --profile full up -d --build

if [ -x .venv/bin/soclab ]; then
  SOCLAB_BIN=".venv/bin/soclab"
elif command -v uv >/dev/null 2>&1; then
  uv sync
  SOCLAB_BIN=".venv/bin/soclab"
else
  SOCLAB_BIN="soclab"
fi

echo "Waiting for SOC Lab API, Wazuh Dashboard, Shuffle Backend, and Shuffle UI..."
for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:8080/health >/dev/null && curl -skf https://127.0.0.1 >/dev/null && curl -sf http://127.0.0.1:5001/api/v1/health >/dev/null && curl -sf http://127.0.0.1:3001 >/dev/null; then
    break
  fi
  sleep 3
done

for attempt in $(seq 1 6); do
  if "$SOCLAB_BIN" lab provision; then
    break
  fi
  echo "Provisioning retry $attempt/6 (waiting for Shuffle apps)..."
  sleep 15
done

"$SOCLAB_BIN" stage4 verify --quick
echo
echo "Open SOC Lab Ready:"
echo "  Wazuh Dashboard : https://localhost (admin / SecretPassword)"
echo "  Shuffle SOAR UI : http://localhost:3001 (admin / soclab-shuffle-admin)"
echo "  Mailpit Webmail : http://127.0.0.1:8025"
echo "  SOC Lab API Docs: http://127.0.0.1:8080/docs"
echo "  Linux Web Target: http://127.0.0.1:8081"
