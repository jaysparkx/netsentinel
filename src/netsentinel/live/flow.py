"""
تجميع الحزم إلى "اتصالات" وحساب ميزات NSL-KDD منها.

هذه الوحدة مستقلّة عن scapy عمداً: تستقبل حزماً مبسّطة (PacketInfo) فيمكن
اختبارها بسهولة، ويمكن تغذيتها من أي مصدر (scapy، ملف pcap، أو بيانات صناعية).

المراحل:
    1. تجميع الحزم حسب "مفتاح الاتصال" (5-tuple):
           (بروتوكول، IP المصدر، منفذ المصدر، IP الهدف، منفذ الهدف)
    2. لكل اتصال نحسب الميزات الأساسية: المدة، البايتات، حالة TCP (flag)...
    3. نرتّب الاتصالات زمنياً ونحسب ميزات النافذة الزمنية (آخر ثانيتين)
       وميزات نافذة الجهاز (آخر 255 اتصالاً) — تماماً كما وُصفت في KDD 99.

ما لا نحسبه: ميزات المحتوى (num_failed_logins, root_shell...) لأنها تحتاج
تحليل حمولة التطبيق. لهذا يستخدم الكشف الحي ملف الميزات "live".
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import pandas as pd

# ---------------------------------------------------------------------------
# تحويل رقم المنفذ إلى اسم الخدمة بنفس تسميات NSL-KDD
# ---------------------------------------------------------------------------
TCP_SERVICES = {
    7: "echo", 9: "discard", 11: "systat", 13: "daytime", 15: "netstat", 20: "ftp_data",
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time", 42: "name", 43: "whois",
    53: "domain", 57: "mtp", 70: "gopher", 77: "rje", 79: "finger", 80: "http",
    84: "ctf", 87: "link", 95: "supdup", 101: "hostnames", 102: "iso_tsap",
    105: "csnet_ns", 109: "pop_2", 110: "pop_3", 111: "sunrpc", 113: "auth",
    117: "uucp_path", 119: "nntp", 137: "netbios_ns", 138: "netbios_dgm",
    139: "netbios_ssn", 143: "imap4", 150: "sql_net", 175: "vmnet", 179: "bgp",
    194: "IRC", 210: "Z39_50", 389: "ldap", 443: "http_443", 512: "exec",
    513: "login", 514: "shell", 515: "printer", 520: "efs", 530: "courier",
    540: "uucp", 543: "klogin", 544: "kshell", 5190: "aol", 6667: "IRC",
    8001: "http_8001", 2784: "http_2784",
}
UDP_SERVICES = {53: "domain_u", 69: "tftp_u", 123: "ntp_u"}
ICMP_SERVICES = {8: "eco_i", 0: "ecr_i", 3: "urp_i", 13: "tim_i", 5: "red_i"}


def port_to_service(protocol: str, dst_port: int) -> str:
    """تقريب لتسمية الخدمة. المنافذ غير المعروفة: ‎<1024 → other، وغير ذلك → private."""
    if protocol == "icmp":
        return ICMP_SERVICES.get(dst_port, "oth_i")   # في ICMP نمرّر "النوع" مكان المنفذ
    table = TCP_SERVICES if protocol == "tcp" else UDP_SERVICES
    if dst_port in table:
        return table[dst_port]
    if 6000 <= dst_port <= 6063:
        return "X11"
    return "other" if dst_port < 1024 else "private"


# ---------------------------------------------------------------------------
# تمثيل الحزمة والاتصال
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PacketInfo:
    """حزمة مبسّطة — فقط الحقول التي نحتاجها من ترويسات IP/TCP/UDP/ICMP."""
    timestamp: float
    protocol: str            # "tcp" | "udp" | "icmp"
    src_ip: str
    dst_ip: str
    src_port: int            # لـ ICMP = 0
    dst_port: int            # لـ ICMP = النوع (type)
    payload_len: int
    tcp_flags: str = ""      # مثل "S", "SA", "A", "FA", "R" (أحرف scapy)
    is_bad_fragment: bool = False


@dataclass
class Connection:
    """حالة اتصال واحد أثناء تجميع حزمه."""
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    start: float
    end: float
    src_bytes: int = 0
    dst_bytes: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    # أحداث TCP لتحديد الحالة النهائية
    events: set[str] = field(default_factory=set)

    @property
    def service(self) -> str:
        return port_to_service(self.protocol, self.dst_port)

    @property
    def flag(self) -> str:
        """
        حالة الاتصال بنمط KDD (مشتقّة من مصطلحات Bro/Zeek):
            SF   : اتصال اكتمل بشكل طبيعي
            S0   : SYN أُرسل ولم يأتِ أي رد           ← نموذجي في SYN flood
            REJ  : SYN أُرسل فرُدَّ عليه بـ RST         ← نموذجي في مسح المنافذ
            RSTO : أُنشئ ثم أنهاه المُبادِر بـ RST
            RSTR : أُنشئ ثم أنهاه المستجيب بـ RST
            SH   : SYN ثم FIN من المُبادِر بلا رد
            S1   : أُنشئ ولم يُغلَق بعد
            OTH  : لم نرَ بداية الاتصال (SYN)
        """
        if self.protocol != "tcp":
            return "SF"
        e = self.events
        established = "resp_synack" in e
        if "orig_syn" not in e:
            return "OTH"
        if not established:
            if "resp_rst" in e:
                return "REJ"
            if "orig_fin" in e:
                return "SH"
            return "S0"
        if "orig_rst" in e:
            return "RSTO"
        if "resp_rst" in e:
            return "RSTR"
        if "orig_fin" in e or "resp_fin" in e:
            return "SF"
        return "S1"

    @property
    def is_syn_error(self) -> bool:
        return self.flag in {"S0", "S1", "S2", "S3"}

    @property
    def is_rej_error(self) -> bool:
        return self.flag == "REJ"


# ---------------------------------------------------------------------------
# المرحلة 1: الحزم → اتصالات
# ---------------------------------------------------------------------------
def assemble_connections(packets: list[PacketInfo], idle_timeout: float = 60.0) -> list[Connection]:
    """
    يجمع الحزم في اتصالات ثنائية الاتجاه.

    الحزمة من A إلى B والحزمة من B إلى A تنتميان لنفس الاتصال؛ أول من بدأ
    يُعتبر "المُبادِر" (originator). إذا مرّ idle_timeout ثانية بلا نشاط،
    نعتبر الحزمة التالية بداية اتصال جديد.
    """
    active: dict[tuple, Connection] = {}
    finished: list[Connection] = []

    for pkt in sorted(packets, key=lambda p: p.timestamp):
        fwd = (pkt.protocol, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        rev = (pkt.protocol, pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)
        if pkt.protocol == "icmp":
            rev = fwd  # ICMP بلا منافذ: نعامل كل نوع كاتصال قائم بذاته

        if fwd in active:
            key, from_originator = fwd, True
        elif rev in active:
            key, from_originator = rev, False   # حزمة رد من المستجيب
        else:
            key, from_originator = fwd, True    # بداية اتصال جديد
        conn = active.get(key)

        if conn is not None and pkt.timestamp - conn.end > idle_timeout:
            finished.append(active.pop(key))
            conn, key, from_originator = None, fwd, True

        if conn is None:
            conn = Connection(pkt.protocol, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
                              start=pkt.timestamp, end=pkt.timestamp)
            active[key] = conn

        conn.end = pkt.timestamp
        if from_originator:
            conn.src_bytes += pkt.payload_len
        else:
            conn.dst_bytes += pkt.payload_len
        conn.wrong_fragment += int(pkt.is_bad_fragment)
        if pkt.protocol == "tcp":
            _record_tcp_event(conn, pkt.tcp_flags, from_originator)

    return sorted(finished + list(active.values()), key=lambda c: c.start)


def _record_tcp_event(conn: Connection, flags: str, from_originator: bool) -> None:
    side = "orig" if from_originator else "resp"
    if "U" in flags:
        conn.urgent += 1
    if "S" in flags and "A" in flags and not from_originator:
        conn.events.add("resp_synack")
    elif "S" in flags:
        conn.events.add(f"{side}_syn")
    if "F" in flags:
        conn.events.add(f"{side}_fin")
    if "R" in flags:
        conn.events.add(f"{side}_rst")


# ---------------------------------------------------------------------------
# المرحلة 2 + 3: الاتصالات → جدول ميزات
# ---------------------------------------------------------------------------
TIME_WINDOW_SECONDS = 2.0
# في بيانات NSL-KDD: dst_host_count ≤ 255 و count ≤ 511. نلتزم بنفس الحدود
# حتى لا نعطي النموذج قيماً خارج المدى الذي تدرّب عليه.
HOST_WINDOW_CONNECTIONS = 255
MAX_TIME_COUNT = 511


def _rate(part: int, total: int) -> float:
    return round(part / total, 2) if total else 0.0


def connections_to_features(connections: list[Connection]) -> pd.DataFrame:
    """
    يحوّل قائمة اتصالات (مرتّبة زمنياً) إلى DataFrame بأعمدة ملف "live" +
    أعمدة تعريفية (src_ip, dst_ip, ...) لعرضها في التنبيهات.

    لكل اتصال نُلقي نظرة على "الماضي القريب":
        - نافذة زمنية: كل الاتصالات خلال آخر ثانيتين.
        - نافذة الجهاز: آخر 255 اتصالاً (بغضّ النظر عن الوقت).
    """
    rows = []
    time_window: deque[Connection] = deque()
    host_window: deque[Connection] = deque(maxlen=HOST_WINDOW_CONNECTIONS - 1)  # + الاتصال الحالي

    for conn in connections:
        while time_window and conn.start - time_window[0].start > TIME_WINDOW_SECONDS:
            time_window.popleft()

        rows.append({
            # --- معرّفات (لا تدخل النموذج) ---
            "timestamp": conn.start,
            "src_ip": conn.src_ip, "src_port": conn.src_port,
            "dst_ip": conn.dst_ip, "dst_port": conn.dst_port,
            # --- الميزات الأساسية ---
            "duration": int(round(conn.end - conn.start)),
            "protocol_type": conn.protocol,
            "service": conn.service,
            "flag": conn.flag,
            "src_bytes": conn.src_bytes,
            "dst_bytes": conn.dst_bytes,
            "land": int(conn.src_ip == conn.dst_ip and conn.src_port == conn.dst_port),
            "wrong_fragment": conn.wrong_fragment,
            "urgent": conn.urgent,
            **_time_features(conn, list(time_window) + [conn]),
            **_host_features(conn, list(host_window) + [conn]),
        })
        time_window.append(conn)
        host_window.append(conn)

    return pd.DataFrame(rows)


def _time_features(conn: Connection, window: list[Connection]) -> dict:
    """ميزات آخر ثانيتين (تشمل الاتصال الحالي، كما في KDD)."""
    same_host = [c for c in window if c.dst_ip == conn.dst_ip]
    same_srv = [c for c in window if c.service == conn.service]
    n_host, n_srv = len(same_host), len(same_srv)
    return {
        "count": min(n_host, MAX_TIME_COUNT),
        "srv_count": min(n_srv, MAX_TIME_COUNT),
        "serror_rate": _rate(sum(c.is_syn_error for c in same_host), n_host),
        "srv_serror_rate": _rate(sum(c.is_syn_error for c in same_srv), n_srv),
        "rerror_rate": _rate(sum(c.is_rej_error for c in same_host), n_host),
        "srv_rerror_rate": _rate(sum(c.is_rej_error for c in same_srv), n_srv),
        "same_srv_rate": _rate(sum(c.service == conn.service for c in same_host), n_host),
        "diff_srv_rate": _rate(sum(c.service != conn.service for c in same_host), n_host),
        "srv_diff_host_rate": _rate(sum(c.dst_ip != conn.dst_ip for c in same_srv), n_srv),
    }


def _host_features(conn: Connection, window: list[Connection]) -> dict:
    """ميزات آخر 255 اتصالاً (نافذة الجهاز) الموجّهة لنفس الجهاز الهدف."""
    same_host = [c for c in window if c.dst_ip == conn.dst_ip]
    same_host_srv = [c for c in same_host if c.service == conn.service]
    n_host, n_hs = len(same_host), len(same_host_srv)
    srv_any_host = [c for c in window if c.service == conn.service]
    return {
        "dst_host_count": n_host,
        "dst_host_srv_count": n_hs,
        "dst_host_same_srv_rate": _rate(n_hs, n_host),
        "dst_host_diff_srv_rate": _rate(n_host - n_hs, n_host),
        "dst_host_same_src_port_rate": _rate(sum(c.src_port == conn.src_port for c in same_host), n_host),
        "dst_host_srv_diff_host_rate": _rate(sum(c.dst_ip != conn.dst_ip for c in srv_any_host), len(srv_any_host)),
        "dst_host_serror_rate": _rate(sum(c.is_syn_error for c in same_host), n_host),
        "dst_host_srv_serror_rate": _rate(sum(c.is_syn_error for c in same_host_srv), n_hs),
        "dst_host_rerror_rate": _rate(sum(c.is_rej_error for c in same_host), n_host),
        "dst_host_srv_rerror_rate": _rate(sum(c.is_rej_error for c in same_host_srv), n_hs),
    }
