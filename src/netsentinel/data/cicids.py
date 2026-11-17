# CIC-IDS2017 dataset (Canadian Institute for Cybersecurity).
# 5 days of real traffic from 2017, one CSV per day/attack. Mon = benign only,
# Tue = FTP/SSH brute force, Wed = DoS + Heartbleed, Thu = web attacks + infiltration,
# Fri = botnet, port scan, DDoS.

import hashlib
import logging
import urllib.request
import zipfile

import numpy as np
import pandas as pd

from netsentinel.data.schema import NORMAL_LABEL
from netsentinel.data.spec import DatasetSpec

logger = logging.getLogger(__name__)

CICIDS_DIR = "cicids2017"
CSV_SUBDIR = "MachineLearningCVE"
ZIP_URL = "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/csvs/MachineLearningCSV.zip"
ZIP_SHA256 = "c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928"

DAY_FILES = {
    "monday": ["Monday-WorkingHours.pcap_ISCX.csv"],
    "tuesday": ["Tuesday-WorkingHours.pcap_ISCX.csv"],
    "wednesday": ["Wednesday-workingHours.pcap_ISCX.csv"],
    "thursday": ["Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
                 "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"],
    "friday": ["Friday-WorkingHours-Morning.pcap_ISCX.csv",
               "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
               "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"],
}

# Destination Port is dropped on purpose so the model learns behaviour, not port numbers.
# "Fwd Header Length.1" is a duplicate column, the others are always 0.
DROPPED_COLUMNS = [
    "Destination Port", "Fwd Header Length.1",
    "Bwd PSH Flags", "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
]

FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

ATTACK_CATEGORY = {
    "BENIGN": NORMAL_LABEL,
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Web Attack - Brute Force": "WebAttack", "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Bot": "Bot",
    "Infiltration": "Infiltration",
    "Heartbleed": "Heartbleed",
}
CLASS_NAMES = [NORMAL_LABEL, "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Bot", "Infiltration", "Heartbleed"]


def cicids_dir(raw_dir):
    return raw_dir / CICIDS_DIR


def download_cicids(raw_dir, force=False):
    target_dir = cicids_dir(raw_dir)
    if (target_dir / CSV_SUBDIR).exists() and not force:
        logger.info("CIC-IDS2017 already downloaded")
        return
    target_dir.mkdir(parents=True, exist_ok=True)
    archive = target_dir / "MachineLearningCSV.zip"
    logger.info("downloading CIC-IDS2017 (235 MB)")
    urllib.request.urlretrieve(ZIP_URL, archive)

    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    if sha != ZIP_SHA256:
        archive.unlink()
        raise ValueError(f"sha256 mismatch: {sha}")
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(target_dir)


def _clean_label(label):
    # web attack labels have a broken character in the CSV files
    label = label.strip()
    for broken in ("�", "ï¿½"):
        label = label.replace(broken, "-")
    return " ".join(label.split())


def load_cicids(raw_dir, days=None):
    """Load and clean the CSVs: drop Inf/NaN rows and exact duplicates. Cached as a pickle."""
    days = days or list(DAY_FILES)
    base = cicids_dir(raw_dir)
    cache = base / f"clean_{'_'.join(days)}.pkl"
    if cache.exists():
        return pd.read_pickle(cache)

    frames = []
    for day in days:
        for filename in DAY_FILES[day]:
            path = base / CSV_SUBDIR / filename
            if not path.exists():
                raise FileNotFoundError(f"{path} not found, run: netsentinel download --dataset cicids2017")
            df = pd.read_csv(path, encoding="latin-1", low_memory=False)
            df.columns = df.columns.str.strip()
            df["day"] = day
            frames.append(df)
            logger.info("loaded %s: %d rows", filename, len(df))

    df = pd.concat(frames, ignore_index=True).drop(columns=DROPPED_COLUMNS)
    df["attack"] = df.pop("Label").map(_clean_label)
    df[FEATURES] = df[FEATURES].astype(np.float64).replace([np.inf, -np.inf], np.nan)

    before = len(df)
    df = df.dropna(subset=FEATURES)
    bad = before - len(df)
    df = df.drop_duplicates(subset=FEATURES + ["attack"])
    logger.info("removed %d invalid and %d duplicate rows, %d left", bad, before - bad - len(df), len(df))

    df[FEATURES] = df[FEATURES].astype(np.float32)
    df["category"] = df["attack"].map(ATTACK_CATEGORY)
    if df["category"].isna().any():
        raise ValueError(f"unknown labels: {df.loc[df['category'].isna(), 'attack'].unique()}")
    df["is_attack"] = (df["category"] != NORMAL_LABEL).astype(int)
    df = df.reset_index(drop=True)
    df.to_pickle(cache)
    return df


def cicids_features():
    return list(FEATURES)


def cicids_spec(profile):
    return DatasetSpec(
        name="CIC-IDS2017",
        profile=profile,
        features=list(FEATURES),
        categorical=[],
        skewed=list(FEATURES),  # all flow features are long-tailed
        class_names=CLASS_NAMES,
    )
