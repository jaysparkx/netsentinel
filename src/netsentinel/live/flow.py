# Turn packets into connections and compute the NSL-KDD "live" features for them.
# Kept separate from scapy so it can be tested with hand made packets.

from collections import deque
from dataclasses import dataclass, field

import pandas as pd

# port -> service name, using the NSL-KDD names
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

TIME_WINDOW = 2.0       # seconds
HOST_WINDOW = 255       # connections
MAX_COUNT = 511         # NSL-KDD caps count at 511


def port_to_service(protocol, dst_port):
    if protocol == "icmp":
        return ICMP_SERVICES.get(dst_port, "oth_i")  # for icmp we store the type in dst_port
    table = TCP_SERVICES if protocol == "tcp" else UDP_SERVICES
    if dst_port in table:
        return table[dst_port]
    if 6000 <= dst_port <= 6063:
        return "X11"
    return "other" if dst_port < 1024 else "private"


@dataclass(frozen=True)
class PacketInfo:
    timestamp: float
    protocol: str        # tcp / udp / icmp
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload_len: int
    tcp_flags: str = ""  # scapy style, e.g. "S", "SA", "FA"
    is_bad_fragment: bool = False


@dataclass
class Connection:
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
    events: set = field(default_factory=set)

    @property
    def service(self):
        return port_to_service(self.protocol, self.dst_port)

    @property
    def flag(self):
        # simplified version of the Bro/Zeek connection states used in KDD
        if self.protocol != "tcp":
            return "SF"
        e = self.events
        if "orig_syn" not in e:
            return "OTH"      # we missed the start
        if "resp_synack" not in e:
            if "resp_rst" in e:
                return "REJ"  # closed port
            if "orig_fin" in e:
                return "SH"
            return "S0"       # no answer at all
        if "orig_rst" in e:
            return "RSTO"
        if "resp_rst" in e:
            return "RSTR"
        if "orig_fin" in e or "resp_fin" in e:
            return "SF"
        return "S1"

    @property
    def is_syn_error(self):
        return self.flag in ("S0", "S1", "S2", "S3")

    @property
    def is_rej_error(self):
        return self.flag == "REJ"


def assemble_connections(packets, idle_timeout=60.0):
    """Group packets by 5-tuple (both directions). The side that sent first is the originator."""
    active = {}
    finished = []

    for pkt in sorted(packets, key=lambda p: p.timestamp):
        fwd = (pkt.protocol, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        rev = (pkt.protocol, pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)
        if pkt.protocol == "icmp":
            rev = fwd

        if fwd in active:
            key, from_orig = fwd, True
        elif rev in active:
            key, from_orig = rev, False
        else:
            key, from_orig = fwd, True
        conn = active.get(key)

        # too long without packets -> start a new connection
        if conn is not None and pkt.timestamp - conn.end > idle_timeout:
            finished.append(active.pop(key))
            conn, key, from_orig = None, fwd, True

        if conn is None:
            conn = Connection(pkt.protocol, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
                              start=pkt.timestamp, end=pkt.timestamp)
            active[key] = conn

        conn.end = pkt.timestamp
        if from_orig:
            conn.src_bytes += pkt.payload_len
        else:
            conn.dst_bytes += pkt.payload_len
        conn.wrong_fragment += int(pkt.is_bad_fragment)
        if pkt.protocol == "tcp":
            add_tcp_event(conn, pkt.tcp_flags, from_orig)

    return sorted(finished + list(active.values()), key=lambda c: c.start)


def add_tcp_event(conn, flags, from_orig):
    side = "orig" if from_orig else "resp"
    if "U" in flags:
        conn.urgent += 1
    if "S" in flags and "A" in flags and not from_orig:
        conn.events.add("resp_synack")
    elif "S" in flags:
        conn.events.add(side + "_syn")
    if "F" in flags:
        conn.events.add(side + "_fin")
    if "R" in flags:
        conn.events.add(side + "_rst")


def rate(part, total):
    return round(part / total, 2) if total else 0.0


def connections_to_features(connections):
    """One row per connection: ids, basic features, last-2-seconds and last-255-connections stats."""
    rows = []
    time_window = deque()
    host_window = deque(maxlen=HOST_WINDOW - 1)  # plus the current connection = 255

    for conn in connections:
        while time_window and conn.start - time_window[0].start > TIME_WINDOW:
            time_window.popleft()

        row = {
            "timestamp": conn.start,
            "src_ip": conn.src_ip, "src_port": conn.src_port,
            "dst_ip": conn.dst_ip, "dst_port": conn.dst_port,
            "duration": int(round(conn.end - conn.start)),
            "protocol_type": conn.protocol,
            "service": conn.service,
            "flag": conn.flag,
            "src_bytes": conn.src_bytes,
            "dst_bytes": conn.dst_bytes,
            "land": int(conn.src_ip == conn.dst_ip and conn.src_port == conn.dst_port),
            "wrong_fragment": conn.wrong_fragment,
            "urgent": conn.urgent,
        }
        row.update(time_features(conn, list(time_window) + [conn]))
        row.update(host_features(conn, list(host_window) + [conn]))
        rows.append(row)

        time_window.append(conn)
        host_window.append(conn)

    return pd.DataFrame(rows)


def time_features(conn, window):
    same_host = [c for c in window if c.dst_ip == conn.dst_ip]
    same_srv = [c for c in window if c.service == conn.service]
    n_host, n_srv = len(same_host), len(same_srv)
    return {
        "count": min(n_host, MAX_COUNT),
        "srv_count": min(n_srv, MAX_COUNT),
        "serror_rate": rate(sum(c.is_syn_error for c in same_host), n_host),
        "srv_serror_rate": rate(sum(c.is_syn_error for c in same_srv), n_srv),
        "rerror_rate": rate(sum(c.is_rej_error for c in same_host), n_host),
        "srv_rerror_rate": rate(sum(c.is_rej_error for c in same_srv), n_srv),
        "same_srv_rate": rate(sum(c.service == conn.service for c in same_host), n_host),
        "diff_srv_rate": rate(sum(c.service != conn.service for c in same_host), n_host),
        "srv_diff_host_rate": rate(sum(c.dst_ip != conn.dst_ip for c in same_srv), n_srv),
    }


def host_features(conn, window):
    same_host = [c for c in window if c.dst_ip == conn.dst_ip]
    same_host_srv = [c for c in same_host if c.service == conn.service]
    same_srv = [c for c in window if c.service == conn.service]
    n_host, n_hs = len(same_host), len(same_host_srv)
    return {
        "dst_host_count": n_host,
        "dst_host_srv_count": n_hs,
        "dst_host_same_srv_rate": rate(n_hs, n_host),
        "dst_host_diff_srv_rate": rate(n_host - n_hs, n_host),
        "dst_host_same_src_port_rate": rate(sum(c.src_port == conn.src_port for c in same_host), n_host),
        "dst_host_srv_diff_host_rate": rate(sum(c.dst_ip != conn.dst_ip for c in same_srv), len(same_srv)),
        "dst_host_serror_rate": rate(sum(c.is_syn_error for c in same_host), n_host),
        "dst_host_srv_serror_rate": rate(sum(c.is_syn_error for c in same_host_srv), n_hs),
        "dst_host_rerror_rate": rate(sum(c.is_rej_error for c in same_host), n_host),
        "dst_host_srv_rerror_rate": rate(sum(c.is_rej_error for c in same_host_srv), n_hs),
    }
