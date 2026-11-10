"""اختبارات تحويل الحزم إلى اتصالات وميزات (بدون scapy وبدون شبكة)."""

from netsentinel.data.schema import FEATURE_PROFILES
from netsentinel.live.flow import PacketInfo, assemble_connections, connections_to_features, port_to_service

C, S = "10.0.0.5", "10.0.0.10"


def tcp(t, src, dst, sport, dport, flags, payload=0):
    return PacketInfo(t, "tcp", src, dst, sport, dport, payload, flags)


def test_port_to_service():
    assert port_to_service("tcp", 80) == "http"
    assert port_to_service("udp", 53) == "domain_u"
    assert port_to_service("icmp", 8) == "eco_i"
    assert port_to_service("tcp", 50000) == "private"
    assert port_to_service("tcp", 999) == "other"


def test_complete_session_is_SF_with_bytes():
    pkts = [
        tcp(0.0, C, S, 40000, 80, "S"), tcp(0.01, S, C, 80, 40000, "SA"), tcp(0.02, C, S, 40000, 80, "A"),
        tcp(0.03, C, S, 40000, 80, "PA", 120), tcp(0.04, S, C, 80, 40000, "PA", 900),
        tcp(1.5, C, S, 40000, 80, "FA"), tcp(1.6, S, C, 80, 40000, "FA"),
    ]
    (conn,) = assemble_connections(pkts)
    assert conn.flag == "SF"
    assert (conn.src_bytes, conn.dst_bytes) == (120, 900)
    assert conn.service == "http"


def test_syn_without_reply_is_S0():
    (conn,) = assemble_connections([tcp(0, C, S, 40001, 80, "S")])
    assert conn.flag == "S0"


def test_syn_answered_by_rst_is_REJ():
    (conn,) = assemble_connections([tcp(0, C, S, 40002, 23, "S"), tcp(0.001, S, C, 23, 40002, "RA")])
    assert conn.flag == "REJ"


def test_syn_flood_produces_high_serror_rate():
    pkts = [tcp(i * 0.001, C, S, 10000 + i, 80, "S") for i in range(300)]
    feats = connections_to_features(assemble_connections(pkts))
    last = feats.iloc[-1]
    assert last["count"] == 300
    assert last["serror_rate"] == 1.0
    assert last["dst_host_serror_rate"] == 1.0


def test_feature_frame_contains_full_live_profile():
    pkts = [tcp(0, C, S, 40000, 80, "S"), tcp(0.01, S, C, 80, 40000, "SA")]
    feats = connections_to_features(assemble_connections(pkts))
    assert set(FEATURE_PROFILES["live"]) <= set(feats.columns)


def test_idle_timeout_splits_connections():
    pkts = [tcp(0, C, S, 40000, 80, "S"), tcp(500, C, S, 40000, 80, "S")]
    assert len(assemble_connections(pkts, idle_timeout=60)) == 2


def test_payload_length_survives_snaplen_truncation():
    """tcpdump -s 128 يقطع الحزمة؛ يجب أن نقرأ الطول الحقيقي من ترويسة IP لا من البايتات الملتقَطة."""
    from scapy.all import IP, TCP, Raw, raw
    from netsentinel.live.capture import to_packet_info

    full = IP(src=C, dst=S) / TCP(sport=40000, dport=80, flags="PA") / Raw(b"x" * 1000)
    truncated = IP(raw(full)[:128])                    # ما يراه tcpdump مع snaplen=128
    truncated.time = 0.0
    assert to_packet_info(truncated).payload_len == 1000


def test_header_only_decoding_can_be_enabled_repeatedly():
    """كل التقاط حي يستدعي _require_scapy؛ التفعيل الثاني كان يُسقط الالتقاط (Already filtered)."""
    from netsentinel.live.capture import _require_scapy
    for _ in range(3):
        _require_scapy()
