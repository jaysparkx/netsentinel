# NSL-KDD column names, feature groups and attack categories.

BASIC_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent",
]
# these need the packet payload, so the live capture can't compute them
CONTENT_FEATURES = [
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
]
# stats over the last 2 seconds
TIME_TRAFFIC_FEATURES = [
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
]
# stats over the last connections to the same host
HOST_TRAFFIC_FEATURES = [
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

ALL_FEATURES = BASIC_FEATURES + CONTENT_FEATURES + TIME_TRAFFIC_FEATURES + HOST_TRAFFIC_FEATURES
RAW_COLUMNS = ALL_FEATURES + ["attack", "difficulty"]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
CONSTANT_FEATURES = ["num_outbound_cmds"]  # always 0 in NSL-KDD

# long-tailed columns, we apply log(1+x) to these
SKEWED_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "hot", "num_compromised", "num_root",
    "num_file_creations", "num_access_files", "count", "srv_count",
    "dst_host_count", "dst_host_srv_count", "wrong_fragment", "urgent",
    "num_failed_logins", "num_shells",
]

FEATURE_PROFILES = {
    "full": [f for f in ALL_FEATURES if f not in CONSTANT_FEATURES],
    "live": BASIC_FEATURES + TIME_TRAFFIC_FEATURES + HOST_TRAFFIC_FEATURES,
}

NORMAL_LABEL = "normal"
CLASS_NAMES = ["normal", "DoS", "Probe", "R2L", "U2R"]

ATTACK_CATEGORY = {}
for name in ["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
             "udpstorm", "processtable", "worm", "mailbomb"]:
    ATTACK_CATEGORY[name] = "DoS"
for name in ["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"]:
    ATTACK_CATEGORY[name] = "Probe"
for name in ["guess_passwd", "ftp_write", "imap", "phf", "multihop", "warezmaster",
             "warezclient", "spy", "xlock", "xsnoop", "snmpguess", "snmpgetattack",
             "httptunnel", "sendmail", "named"]:
    ATTACK_CATEGORY[name] = "R2L"
for name in ["buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack", "xterm", "ps"]:
    ATTACK_CATEGORY[name] = "U2R"


def attack_to_category(attack):
    if attack == NORMAL_LABEL:
        return NORMAL_LABEL
    if attack not in ATTACK_CATEGORY:
        raise ValueError(f"unknown attack name: {attack}")
    return ATTACK_CATEGORY[attack]


# used to explain alerts
FEATURE_DESCRIPTIONS = {
    "duration": "connection length in seconds",
    "protocol_type": "protocol (tcp/udp/icmp)",
    "service": "service on the target",
    "flag": "TCP state (SF normal, S0 no reply, REJ rejected)",
    "src_bytes": "bytes from source to target",
    "dst_bytes": "bytes from target to source",
    "land": "source and target are the same",
    "wrong_fragment": "wrong fragments",
    "urgent": "urgent packets",
    "hot": "hot indicators",
    "num_failed_logins": "failed logins",
    "logged_in": "login succeeded",
    "num_compromised": "compromised conditions",
    "root_shell": "root shell obtained",
    "su_attempted": "su root attempted",
    "num_root": "root accesses",
    "num_file_creations": "file creations",
    "num_shells": "shell prompts",
    "num_access_files": "access to control files",
    "num_outbound_cmds": "outbound ftp commands",
    "is_host_login": "host login",
    "is_guest_login": "guest login",
    "count": "connections to same host in last 2s",
    "srv_count": "connections to same service in last 2s",
    "serror_rate": "SYN error rate, same host (2s)",
    "srv_serror_rate": "SYN error rate, same service (2s)",
    "rerror_rate": "REJ rate, same host (2s)",
    "srv_rerror_rate": "REJ rate, same service (2s)",
    "same_srv_rate": "same service rate (2s)",
    "diff_srv_rate": "different services rate (2s)",
    "srv_diff_host_rate": "different hosts rate (2s)",
    "dst_host_count": "connections to same host (window)",
    "dst_host_srv_count": "connections to same host+service (window)",
    "dst_host_same_srv_rate": "same service rate on host (window)",
    "dst_host_diff_srv_rate": "different services on host (window)",
    "dst_host_same_src_port_rate": "same source port rate (window)",
    "dst_host_srv_diff_host_rate": "different hosts for service (window)",
    "dst_host_serror_rate": "SYN error rate on host (window)",
    "dst_host_srv_serror_rate": "SYN error rate on host+service (window)",
    "dst_host_rerror_rate": "REJ rate on host (window)",
    "dst_host_srv_rerror_rate": "REJ rate on host+service (window)",
}

CATEGORY_DESCRIPTIONS = {
    "normal": "normal traffic",
    "DoS": "denial of service",
    "Probe": "scan / probe",
    "R2L": "remote login attempt",
    "U2R": "privilege escalation",
    "Unknown-Anomaly": "unusual behaviour, possibly a new attack",
}
