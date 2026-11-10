"""
الالتقاط الحي وقراءة ملفات pcap باستخدام Scapy.

    pcap  → قراءة ملف مسجّل مسبقاً (Wireshark / tcpdump) — لا يحتاج صلاحيات root.
    live  → التقاط من كرت الشبكة مباشرة — يحتاج sudo (Linux/macOS) أو Npcap (Windows).

⚠️ أخلاقيات وقانون: التقط فقط على شبكة تملكها أو لديك إذن كتابي بمراقبتها.
"""

from __future__ import annotations

import logging
import time
from collections import deque
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
    _enlarge_bpf_buffer()
    return scapy


def _enlarge_bpf_buffer() -> None:
    """
    macOS/BSD: نكبّر مخزن الالتقاط في نواة النظام (BPF) من 64 KB إلى الحدّ الأقصى المسموح.

    لماذا؟ مسح nmap يرسل ~4000 حزمة في أقل من ثانية. مخزن 64 KB يتّسع لنحو 800 حزمة
    فقط، والباقي تُسقطه النواة قبل أن يقرأه بايثون — فلم تُرَ أغلب حزم المسح في العرض الحي.
    (tcpdump لم يُعانِ من ذلك لأنه يستخدم مخزناً أكبر.)

    ملاحظة تقنية: على BPF يجب أن يكون حجم القراءة مساوياً لحجم المخزن تماماً، لذلك
    نعدّل القيمة الافتراضية لدوال القراءة في Scapy أيضاً، لا الثابت فقط.
    """
    try:
        import scapy.arch.bpf.supersocket as bpf
    except ImportError:          # ليس macOS/BSD (مثلاً Linux) — لا حاجة
        return
    size = _bpf_max_buffer()
    if getattr(bpf, "_netsentinel_patched", False):
        return
    bpf.BPF_BUFFER_LENGTH = size
    # sniff() يستدعي recv(x=65535) دائماً؛ نجبر القراءة على حجم المخزن كاملاً وإلا رفضتها النواة.
    for cls in (bpf.L2bpfListenSocket, bpf._L2bpfSocket):
        original = cls.recv_raw

        def recv_raw(self, x=size, _original=original):
            return _original(self, size)

        cls.recv_raw = recv_raw
    if bpf.L3bpfSocket.recv.__defaults__:
        bpf.L3bpfSocket.recv.__defaults__ = (size,) + bpf.L3bpfSocket.recv.__defaults__[1:]
    bpf._netsentinel_patched = True


def _bpf_max_buffer(default: int = 524288) -> int:
    """أكبر مخزن BPF يسمح به النظام (sysctl debug.bpf_maxbufsize)، بحدّ أقصى 4 MB."""
    import subprocess
    try:
        out = subprocess.run(["sysctl", "-n", "debug.bpf_maxbufsize"], capture_output=True, text=True, timeout=2)
        return min(int(out.stdout.strip()), 4 * 1024 * 1024)
    except (OSError, ValueError, subprocess.SubprocessError):
        return default


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
                          max(ip_payload - (seg.dataofs or 5) * 4, 0), str(seg.flags), bad_frag)
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
    if ip.len and ip.ihl:
        return int(ip.len) - int(ip.ihl) * 4
    return len(ip.payload)   # الحقل صفر (TSO) أو غير محسوب بعد — نرجع لطول الحمولة الملتقَطة


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
    يلتقط باستمرار دون أي فجوة، ويحلّل كل batch_seconds:

        خيط الالتقاط (AsyncSniffer) ── يستمع طوال الوقت ويضع كل حزمة في طابور
        الحلقة هنا ── كل batch_seconds: تسحب الحزم الجديدة من الطابور ←
                       تحسب الميزات على حزم آخر context_seconds (حتى تكون نوافذ
                       "آخر 255 اتصالاً" ممتلئة بالسياق الصحيح) ←
                       تمرّر إلى on_batch فقط الاتصالات التي بدأت منذ آخر دفعة.

    لماذا خيطان؟ في النسخة الأولى كنا نلتقط 3 ثوانٍ ثم نحلّل — وأثناء التحليل لا أحد
    يستمع، فضاع أغلب مسح nmap (ثانية واحدة) وأغلب الـ flood. (اكتُشف في عرض حيّ.)

    أوقفه بـ Ctrl+C، أو بإرجاع True من should_stop (تستخدمه الواجهة عند إغلاق المتصفّح).
    """
    scapy = _require_scapy()
    incoming: deque[PacketInfo] = deque()

    def on_packet(pkt) -> None:            # يعمل في خيط الالتقاط: خفيف وسريع عمداً
        try:
            info = to_packet_info(pkt)
        except Exception:                  # حزمة واحدة غريبة لا يجب أن توقف الالتقاط كله
            logger.debug("تجاهل حزمة تعذّر فكّها", exc_info=True)
            return
        if info is not None:
            incoming.append(info)

    sniffer = scapy.AsyncSniffer(iface=interface, filter=bpf_filter, store=False, prn=on_packet)
    sniffer.start()
    logger.info("بدء الالتقاط على %s (تحليل كل %.0f ث) — Ctrl+C للإيقاف", interface or "الواجهة الافتراضية", batch_seconds)

    buffer: list[PacketInfo] = []
    reported: dict[tuple, float] = {}      # الاتصالات التي أبلغنا عنها ← وقت بدايتها
    key_cols = ["protocol_type", "src_ip", "src_port", "dst_ip", "dst_port", "timestamp"]
    try:
        while not (should_stop and should_stop()):
            time.sleep(batch_seconds)
            while incoming:
                buffer.append(incoming.popleft())
            now = time.time()
            buffer = [p for p in buffer if p.timestamp >= now - context_seconds]
            reported = {k: t for k, t in reported.items() if t >= now - context_seconds}
            if not buffer:
                continue
            try:
                features = connections_to_features(assemble_connections(buffer))
                # نُبلّغ عن كل اتصال مرة واحدة فقط — بهويته (5-tuple + وقت البداية) لا بالساعة،
                # فلا يضيع اتصال بدأ قبل لحظة التحليل ووصلت حزمته بعدها.
                keys = list(features[key_cols].itertuples(index=False, name=None))
                is_new = [k not in reported for k in keys]
                fresh = features[is_new]
                for k in (k for k, new in zip(keys, is_new) if new):
                    reported[k] = k[-1]
                if not fresh.empty:
                    on_batch(fresh.reset_index(drop=True))
            except Exception:   # دفعة فاشلة لا يجب أن توقف المراقبة كلها
                logger.exception("فشل تحليل دفعة — نتابع بالدفعة التالية")
    finally:
        sniffer.stop(join=False)
