#!/usr/bin/env bash
# =============================================================================
#  التقاط حركة حقيقية على جهازك أنت — لاختبار NetSentinel على حزم حقيقية.
#
#  كل شيء يحدث على واجهة الـ loopback (127.0.0.1) فقط: الهجمات موجّهة إلى
#  جهازك نفسه، ولا تخرج حزمة واحدة إلى أي شبكة. آمن وقانوني تماماً.
#
#  ما الذي يُنتجه:
#    data/real/real_normal.pcap  : 60 ثانية تصفّح طبيعي لخادم ويب محلي
#    data/real/real_attack.pcap  : تصفّح طبيعي + 3 هجمات حقيقية بأدوات حقيقية:
#         1) nmap SYN scan  (مسح منافذ حقيقي — Probe)
#         2) nmap connect scan مع كشف الخدمات (-sV)
#         3) HTTP flood: آلاف الطلبات المتوازية لخادم الويب (DoS مصغّر)
#
#  المتطلّبات: macOS أو Linux، nmap (brew install nmap)، Python 3.
#  التشغيل (يحتاج sudo لأن التقاط الحزم يحتاج صلاحيات root):
#      sudo bash tools/capture_real_traffic.sh
#  ثم:
#      netsentinel pcap data/real/real_attack.pcap
# =============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "شغّله بـ sudo:  sudo bash $0" >&2
  exit 1
fi
command -v nmap >/dev/null || { echo "nmap غير مثبّت: brew install nmap" >&2; exit 1; }

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$PROJECT_DIR/data/real"
mkdir -p "$OUT_DIR"
IFACE=$( [[ "$(uname)" == "Darwin" ]] && echo lo0 || echo lo )
PORT=8088
REAL_USER="${SUDO_USER:-$USER}"

# خادم ويب محلي بسيط (يعمل كمستخدم عادي، ليس root)
sudo -u "$REAL_USER" python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$PROJECT_DIR/docs" \
  >/dev/null 2>&1 &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" "${TCPDUMP_PID:-}" "${BROWSE_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT
sleep 1

browse() {  # تصفّح "بشري": طلب كل 0.2–1.5 ثانية لصفحات مختلفة
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

echo "① التقاط حركة طبيعية (60 ثانية)..."
capture_start "$OUT_DIR/real_normal.pcap"
browse 60
capture_stop "$OUT_DIR/real_normal.pcap"

echo "② التقاط حركة طبيعية + هجمات حقيقية (~90 ثانية)..."
capture_start "$OUT_DIR/real_attack.pcap"
browse 90 & BROWSE_PID=$!
sleep 10
echo "   → nmap SYN scan (المنافذ 1–2000)"
nmap -sS -p 1-2000 -T4 127.0.0.1 >/dev/null
sleep 10
echo "   → nmap service detection scan"
nmap -sT -sV --top-ports 100 127.0.0.1 >/dev/null
sleep 10
echo "   → HTTP flood (3000 طلب، 100 متوازية)"
seq 3000 | xargs -P 100 -I{} curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" || true
wait "$BROWSE_PID" || true
capture_stop "$OUT_DIR/real_attack.pcap"

echo "✓ جاهز:"
ls -lh "$OUT_DIR"/*.pcap
echo
echo "التالي:  netsentinel pcap data/real/real_normal.pcap"
echo "         netsentinel pcap data/real/real_attack.pcap"
