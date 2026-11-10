"""
الالتقاط الحي وقراءة ملفات pcap باستخدام Scapy.

    pcap  → قراءة ملف مسجّل مسبقاً (Wireshark / tcpdump) — لا يحتاج صلاحيات root.
    live  → التقاط من كرت الشبكة مباشرة — يحتاج sudo (Linux/macOS) أو Npcap (Windows).

⚠️ أخلاقيات وقانون: التقط فقط على شبكة تملكها أو لديك إذن كتابي بمراقبتها.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable

import pandas as pd

from netsentinel.live.flow import PacketInfo, assemble_connections, connections_to_features

logger = logging.getLogger(__name__)


def _require_scapy():
    try:
        import scapy.all as scapy  # noqa: F401
    except ImportError as exc:
        raise ImportError("Live capture needs scapy:  pip install 'netsentinel[live]'") from exc
    _decode_headers_only(scapy)
    return scapy


def _decode_headers_only(scapy) -> None:
    """
    نطلب من Scapy فكّ الترويسات التي نحتاجها فقط (Ethernet/Loopback, IP, TCP, UDP, ICMP)
    ويترك الحمولة كبايتات خام. لماذا؟ أثناء HTTP flood حاول Scapy تحليل حمولة إحدى
    الحزم بعمق فانهار بخطأ "maximum recursion depth" وتوقّف الالتقاط الحي بصمت.
    (اكتُشف أثناء عرض حيّ.) ونكسب سرعة أيضاً لأننا لا نقرأ المحتوى أصلاً.
    """
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import Ether, Loopback

    if not getattr(scapy.conf.layers, "filtered", False):   # Scapy يرفض التفعيل مرتين
        scapy.conf.layers.filter([Ether, Loopback, IP, TCP, UDP, ICMP])


def to_packet_info(pkt) -> PacketInfo | None:
    """يحوّل حزمة scapy إلى PacketInfo، أو None إذا لم تكن IPv4 TCP/UDP/ICMP."""
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    if IP not in pkt:
        return None
    ip = pkt[IP]
    # جزء غير صحيح: إزاحة غير صفرية مع حجم صغير جداً (نمط هجوم teardrop تقريباً)
    bad_frag = bool(ip.frag and len(ip.payload) < 8)
    ip_payload = _ip_payload_length(ip)

    if TCP in pkt:
        seg = pkt[TCP]
        return PacketInfo(float(pkt.time), "tcp", ip.src, ip.dst, seg.sport, seg.dport,
                          max(ip_payload - seg.dataofs * 4, 0), str(seg.flags), bad_frag)
    if UDP in pkt:
        seg = pkt[UDP]
        return PacketInfo(float(pkt.time), "udp", ip.src, ip.dst, seg.sport, seg.dport,
                          max(ip_payload - 8, 0), "", bad_frag)
    if ICMP in pkt:
        icmp = pkt[ICMP]
        return PacketInfo(float(pkt.time), "icmp", ip.src, ip.dst, 0, int(icmp.type),
                          max(ip_payload - 8, 0), "", bad_frag)
    return None


def _ip_payload_length(ip) -> int:
    """
    الطول الحقيقي لما بعد ترويسة IP، من حقل "Total Length" في الترويسة نفسها.

    لماذا لا نستخدم len(payload)؟ لأن tcpdump غالباً يلتقط أول N بايت فقط من كل
    حزمة (snaplen، مثل -s 128) لتوفير المساحة وحماية الخصوصية. عندها len(payload)
    يُرجع الجزء الملتقَط فقط، فتبدو كل الحزم صغيرة. (اكتشفنا هذا الخطأ عند تجربة
    حزم حقيقية — الحزم الصناعية كانت كاملة فلم يظهر.)
    """
    if ip.len:
        return int(ip.len) - int(ip.ihl) * 4
    return len(ip.payload)   # بعض أنظمة الإرسال (TSO) تترك الحقل صفراً


def packets_to_features(packets: Iterable) -> pd.DataFrame:
    """حزم scapy → جدول ميزات بنمط NSL-KDD (ملف live)."""
    infos = [info for info in (to_packet_info(p) for p in packets) if info is not None]
    return connections_to_features(assemble_connections(infos))


def read_pcap_features(path: str) -> pd.DataFrame:
    """يقرأ ملف pcap كاملاً ويُرجع جدول الميزات."""
    scapy = _require_scapy()
    packets = scapy.rdpcap(path)
    logger.info("قُرئت %d حزمة من %s", len(packets), path)
    return packets_to_features(packets)


def live_capture(
    on_batch: Callable[[pd.DataFrame], None],
    interface: str | None = None,
    batch_seconds: float = 10.0,
    context_seconds: float = 120.0,
    bpf_filter: str = "ip",
    should_stop: Callable[[], bool] | None = None,
) -> None:
    """
    يلتقط باستمرار على دفعات. بعد كل دفعة:
        1. يحسب الميزات على حزم آخر context_seconds (حتى تكون نوافذ
           "آخر 255 اتصالاً" ممتلئة بالسياق الصحيح).
        2. يمرّر إلى on_batch فقط الاتصالات التي بدأت في الدفعة الأخيرة
           (حتى لا نُبلّغ عن نفس الاتصال مرتين).
    أوقفه بـ Ctrl+C، أو بإرجاع True من should_stop (تستخدمه الواجهة عند إغلاق المتصفّح).
    """
    scapy = _require_scapy()
    buffer: list[PacketInfo] = []
    logger.info("بدء الالتقاط على %s (دفعة كل %.0f ث) — Ctrl+C للإيقاف", interface or "الواجهة الافتراضية", batch_seconds)

    while not (should_stop and should_stop()):
        batch_start = time.time()
        try:
            packets = scapy.sniff(iface=interface, timeout=batch_seconds, filter=bpf_filter, store=True)
        except Exception:   # دفعة فاشلة لا يجب أن توقف المراقبة كلها
            logger.exception("فشلت دفعة التقاط — نتابع بالدفعة التالية")
            continue
        buffer.extend(i for i in (to_packet_info(p) for p in packets) if i is not None)
        buffer = [p for p in buffer if p.timestamp >= batch_start - context_seconds]
        if not buffer:
            continue
        features = connections_to_features(assemble_connections(buffer))
        fresh = features[features["timestamp"] >= batch_start]
        if not fresh.empty:
            on_batch(fresh.reset_index(drop=True))
