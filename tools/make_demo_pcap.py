"""
يولّد ملفات pcap صناعية للعرض والاختبار — بدون الحاجة لشبكة حقيقية أو صلاحيات.

    demo_normal.pcap  : حركة طبيعية فقط (تصفّح HTTP + استعلامات DNS)
    demo_attack.pcap  : حركة طبيعية + 3 هجمات:
        1. SYN Flood     (DoS)   — آلاف حزم SYN لمنفذ 80 بلا إكمال المصافحة
        2. Port Scan     (Probe) — SYN لمئات المنافذ، والهدف يرد بـ RST
        3. Ping Sweep    (Probe) — ICMP Echo لكل عناوين الشبكة الفرعية

الحزم مصنوعة بـ Scapy ولا تُرسَل لأي شبكة — تُكتب في ملف فقط.

الاستخدام:
    python tools/make_demo_pcap.py --out data/demo
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Raw, wrpcap

SERVER = "10.0.0.10"
CLIENTS = [f"10.0.0.{i}" for i in range(50, 70)]
ATTACKER = "203.0.113.66"   # عنوان من نطاق التوثيق (TEST-NET-3) — ليس حقيقياً


def http_session(client: str, t: float, sport: int) -> list:
    """جلسة HTTP كاملة: مصافحة ثلاثية ← طلب ← رد ← إغلاق بـ FIN."""
    c2s = IP(src=client, dst=SERVER) / TCP(sport=sport, dport=80)
    s2c = IP(src=SERVER, dst=client) / TCP(sport=80, dport=sport)
    pkts = [
        c2s.copy(), s2c.copy(), c2s.copy(),
        c2s / Raw(b"GET /index.html HTTP/1.1\r\nHost: intranet\r\n\r\n"),
        s2c / Raw(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * random.randint(300, 4000)),
        c2s.copy(), s2c.copy(),
    ]
    flags = ["S", "SA", "A", "PA", "PA", "FA", "FA"]
    for i, (p, f) in enumerate(zip(pkts, flags)):
        p[TCP].flags = f
        p.time = t + i * 0.01
    return pkts


def dns_query(client: str, t: float) -> list:
    q = IP(src=client, dst="10.0.0.1") / UDP(sport=random.randint(30000, 60000), dport=53) / DNS(
        rd=1, qd=DNSQR(qname="intranet.local"))
    r = IP(src="10.0.0.1", dst=client) / UDP(sport=53, dport=q[UDP].sport) / Raw(b"\x00" * 60)
    q.time, r.time = t, t + 0.005
    return [q, r]


def normal_traffic(start: float, duration: float, rate: float = 4.0) -> list:
    """حركة طبيعية: ~rate جلسة في الثانية بين عملاء متعدّدين والخادم."""
    pkts, t = [], start
    while t < start + duration:
        client = random.choice(CLIENTS)
        if random.random() < 0.75:
            pkts += http_session(client, t, random.randint(40000, 60000))
        else:
            pkts += dns_query(client, t)
        t += random.expovariate(rate)
    return pkts


def syn_flood(start: float, n: int = 3000) -> list:
    """DoS: SYN بلا إكمال ← الخادم يحجز موارد لاتصالات نصف مفتوحة (S0)."""
    pkts = []
    for i in range(n):
        p = IP(src=ATTACKER, dst=SERVER) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        p.time = start + i * 0.001
        pkts.append(p)
    return pkts


def port_scan(start: float, ports=range(1, 600)) -> list:
    """Probe: SYN لكل منفذ ← المنافذ المغلقة ترد RST (REJ)."""
    pkts = []
    for i, port in enumerate(ports):
        syn = IP(src=ATTACKER, dst=SERVER) / TCP(sport=45555, dport=port, flags="S")
        rst = IP(src=SERVER, dst=ATTACKER) / TCP(sport=port, dport=45555, flags="RA")
        syn.time, rst.time = start + i * 0.002, start + i * 0.002 + 0.0005
        pkts += [syn, rst]
    return pkts


def ping_sweep(start: float) -> list:
    """Probe: ICMP Echo لكل جهاز في الشبكة الفرعية لاكتشاف الأجهزة الحيّة."""
    pkts = []
    for i in range(1, 255):
        p = IP(src=ATTACKER, dst=f"10.0.1.{i}") / ICMP(type=8) / Raw(b"\x00" * 18)
        p.time = start + i * 0.003
        pkts.append(p)
    return pkts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="data/demo")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    random.seed(args.seed)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    t0 = 1_700_000_000.0
    normal = normal_traffic(t0, duration=300)
    wrpcap(str(out / "demo_normal.pcap"), sorted(normal, key=lambda p: p.time))

    attack = normal_traffic(t0, duration=120) + syn_flood(t0 + 30) + port_scan(t0 + 60) + ping_sweep(t0 + 90)
    wrpcap(str(out / "demo_attack.pcap"), sorted(attack, key=lambda p: p.time))
    print(f"✓ {out / 'demo_normal.pcap'}  ({len(normal):,} حزمة)")
    print(f"✓ {out / 'demo_attack.pcap'}  ({len(attack):,} حزمة)")


if __name__ == "__main__":
    main()
