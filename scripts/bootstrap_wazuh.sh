#!/usr/bin/env bash
set -Eeuo pipefail

# Bootstraps the official Wazuh single-node Docker stack.
# Run on Linux, or inside WSL2 when Docker Desktop is used on Windows.

WAZUH_DOCKER_TAG="${WAZUH_DOCKER_TAG:-v4.14.8}"
TARGET_DIR="${1:-.runtime/wazuh-docker}"

for command in git docker; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "ERROR: '$command' is required." >&2
    exit 1
  fi
done

docker compose version >/dev/null

if command -v sysctl >/dev/null 2>&1; then
  current="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
  if [ "${current:-0}" -lt 262144 ]; then
    echo "vm.max_map_count=${current}; Wazuh requires at least 262144."
    echo "Run: sudo sysctl -w vm.max_map_count=262144"
    exit 1
  fi
fi

if [ ! -d "$TARGET_DIR/.git" ]; then
  mkdir -p "$(dirname "$TARGET_DIR")"
  git clone --depth 1 --branch "$WAZUH_DOCKER_TAG" \
    https://github.com/wazuh/wazuh-docker.git "$TARGET_DIR"
else
  echo "Using existing Wazuh Docker checkout: $TARGET_DIR"
fi

cd "$TARGET_DIR/single-node"

if [ ! -f config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
  echo "Generating Wazuh self-signed certificates..."
  docker compose -f generate-indexer-certs.yml run --rm generator
else
  echo "Certificates already exist; skipping generation."
fi

echo "Starting Wazuh single-node stack..."
docker compose up -d

echo
echo "Wazuh is starting. Check containers with:"
echo "  cd '$TARGET_DIR/single-node' && docker compose ps"
echo
echo "Dashboard: https://localhost"
echo "API:       https://localhost:55000"
echo
echo "IMPORTANT: change all default lab passwords before exposing this host to another network."
