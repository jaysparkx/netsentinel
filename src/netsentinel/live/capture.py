# Reading pcap files and live capture with scapy.
# Live capture needs root (sudo). Only capture on networks you are allowed to monitor.

import logging
import subprocess
import time
from collections import deque

from netsentinel.live.flow import PacketInfo, assemble_connections, connections_to_features

logger = logging.getLogger(__name__)


def _require_scapy():
    try:
        import scapy.all as scapy
    except ImportError:
        raise ImportError("live capture needs scapy: pip install 'netsentinel[live]'")

    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import Ether, Loopback

    # only decode the headers we use. Decoding payloads crashed scapy during the HTTP flood test.
    if not scapy.conf.layers.filtered:
        scapy.conf.layers.filter([Ether, Loopback, IP, TCP, UDP, ICMP])
    _bigger_bpf_buffer()
    return scapy


def _bigger_bpf_buffer():
    # mac: default 64KB buffer drops packets during nmap, make it bigger
    try:
        import scapy.arch.bpf.supersocket as bpf
    except ImportError:
        return  # linux, nothing to do
    if getattr(bpf, "_patched", False):
        return

    try:
        out = subprocess.run(["sysctl", "-n", "debug.bpf_maxbufsize"], capture_output=True, text=True)
        size = min(int(out.stdout.strip()), 4 * 1024 * 1024)
    except (OSError, ValueError):
        size = 524288

    bpf.BPF_BUFFER_LENGTH = size
    for cls in (bpf.L2bpfListenSocket, bpf._L2bpfSocket):
        old = cls.recv_raw

        def recv_raw(self, x=size, old=old):
            return old(self, size)

        cls.recv_raw = recv_raw
    if bpf.L3bpfSocket.recv.__defaults__:
        bpf.L3bpfSocket.recv.__defaults__ = (size,) + bpf.L3bpfSocket.recv.__defaults__[1:]
    bpf._patched = True


def ip_payload_length(ip):
    # use the IP total length field, not len(payload): tcpdump -s 128 cuts packets short
    if ip.len and ip.ihl:
        return int(ip.len) - int(ip.ihl) * 4
    return len(ip.payload)


def to_packet_info(pkt):
    """scapy packet -> PacketInfo (None if it isn't IPv4 tcp/udp/icmp)."""
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    if IP not in pkt:
        return None
    ip = pkt[IP]
    bad_frag = bool(ip.frag and len(ip.payload) < 8)
    size = ip_payload_length(ip)

    if TCP in pkt:
        t = pkt[TCP]
        return PacketInfo(float(pkt.time), "tcp", ip.src, ip.dst, t.sport, t.dport,
                          max(size - (t.dataofs or 5) * 4, 0), str(t.flags), bad_frag)
    if UDP in pkt:
        u = pkt[UDP]
        return PacketInfo(float(pkt.time), "udp", ip.src, ip.dst, u.sport, u.dport,
                          max(size - 8, 0), "", bad_frag)
    if ICMP in pkt:
        return PacketInfo(float(pkt.time), "icmp", ip.src, ip.dst, 0, int(pkt[ICMP].type),
                          max(size - 8, 0), "", bad_frag)
    return None


def packets_to_features(packets):
    infos = [p for p in (to_packet_info(pkt) for pkt in packets) if p is not None]
    return connections_to_features(assemble_connections(infos))


def read_pcap_features(path):
    scapy = _require_scapy()
    packets = scapy.rdpcap(path)
    logger.info("read %d packets from %s", len(packets), path)
    return packets_to_features(packets)


def live_capture(on_batch, interface=None, batch_seconds=10.0, context_seconds=120.0,
                 bpf_filter="ip", should_stop=None):
    # sniff in background, analyse every batch_seconds, report each connection once
    scapy = _require_scapy()
    incoming = deque()

    def on_packet(pkt):
        try:
            info = to_packet_info(pkt)
        except Exception:
            return  # skip packets we can't parse
        if info is not None:
            incoming.append(info)

    sniffer = scapy.AsyncSniffer(iface=interface, filter=bpf_filter, store=False, prn=on_packet)
    sniffer.start()
    logger.info("capturing on %s", interface or "default interface")

    buffer = []
    reported = {}   # connection key -> start time
    key_cols = ["protocol_type", "src_ip", "src_port", "dst_ip", "dst_port", "timestamp"]
    try:
        while not (should_stop and should_stop()):
            time.sleep(batch_seconds)
            while incoming:
                buffer.append(incoming.popleft())

            # keep the last context_seconds so the window features have history
            now = time.time()
            buffer = [p for p in buffer if p.timestamp >= now - context_seconds]
            reported = {k: t for k, t in reported.items() if t >= now - context_seconds}
            if not buffer:
                continue

            try:
                features = connections_to_features(assemble_connections(buffer))
                keys = list(features[key_cols].itertuples(index=False, name=None))
                new = [k not in reported for k in keys]
                for k, is_new in zip(keys, new):
                    if is_new:
                        reported[k] = k[-1]
                fresh = features[new]
                if not fresh.empty:
                    on_batch(fresh.reset_index(drop=True))
            except Exception:
                logger.exception("batch failed, continuing")
    finally:
        sniffer.stop(join=False)
