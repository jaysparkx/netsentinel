#!/usr/bin/env bash
# Records real traffic on this machine (127.0.0.1 only) for testing:
#   data/real/real_normal.pcap  - 60s of browsing a local web server
#   data/real/real_attack.pcap  - browsing + nmap SYN scan + nmap -sV + HTTP flood
# Needs root for tcpdump:  sudo bash tools/capture_real_traffic.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo: sudo bash $0" >&2
  exit 1
fi
command -v nmap >/dev/null || { echo "nmap not installed: brew install nmap" >&2; exit 1; }

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$PROJECT_DIR/data/real"
mkdir -p "$OUT_DIR"
IFACE=$( [[ "$(uname)" == "Darwin" ]] && echo lo0 || echo lo )
PORT=8088
REAL_USER="${SUDO_USER:-$USER}"

# local web server, runs as the normal user
sudo -u "$REAL_USER" python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$PROJECT_DIR/docs" \
  >/dev/null 2>&1 &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" "${TCPDUMP_PID:-}" "${BROWSE_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT
sleep 1

browse() {
  local end=$((SECONDS + $1))
  local pages=(01_idea_and_problem.md 02_dataset.md 03_architecture.md 04_models_and_algorithms.md "")
  while (( SECONDS < end )); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT/${pages[RANDOM % ${#pages[@]}]}" || true
    sleep "0.$(( (RANDOM % 13) + 2 ))"
  done
}

capture_start() {
  tcpdump -i "$IFACE" -w "$1" -s 128 "host 127.0.0.1" >/dev/null 2>&1 &
  TCPDUMP_PID=$!
  sleep 1
}

capture_stop() {
  sleep 1
  kill "$TCPDUMP_PID"; wait "$TCPDUMP_PID" 2>/dev/null || true
  chown "$REAL_USER" "$1"
}

echo "1) normal traffic (60s)"
capture_start "$OUT_DIR/real_normal.pcap"
browse 60
capture_stop "$OUT_DIR/real_normal.pcap"

echo "2) normal traffic + attacks (~90s)"
capture_start "$OUT_DIR/real_attack.pcap"
browse 90 & BROWSE_PID=$!
sleep 10
echo "   nmap SYN scan"
nmap -sS -p 1-2000 -T4 127.0.0.1 >/dev/null
sleep 10
echo "   nmap service scan"
nmap -sT -sV --top-ports 100 127.0.0.1 >/dev/null
sleep 10
echo "   HTTP flood"
seq 3000 | xargs -P 100 -I{} curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" || true
wait "$BROWSE_PID" || true
capture_stop "$OUT_DIR/real_attack.pcap"

ls -lh "$OUT_DIR"/*.pcap
echo "next: netsentinel pcap data/real/real_attack.pcap"
