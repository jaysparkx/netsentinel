"""
مجموعة بيانات CIC-IDS2017 — حركة شبكة حقيقية حديثة.

المصدر: المعهد الكندي للأمن السيبراني (جامعة نيو برونزويك)
        https://www.unb.ca/cic/datasets/ids-2017.html
        Sharafaldin, Lashkari & Ghorbani (2018), ICISSP.

ما هي؟ شبكة حقيقية من 25 مستخدماً (Windows, Ubuntu, Mac) سُجّلت حركتها 5 أيام
عمل كاملة (3–7 تموز 2017)، ونُفّذت خلالها هجمات حقيقية بأدوات حقيقية
(LOIC, Hulk, Patator, Metasploit, Ares botnet...). حُوّلت الحزم إلى "تدفّقات"
(Flows) بأداة CICFlowMeter التي تحسب ~80 ميزة إحصائية لكل تدفّق.

    ┌───────────┬──────────────────────────────────────────────────────┐
    │ اليوم     │ الهجمات                                               │
    ├───────────┼──────────────────────────────────────────────────────┤
    │ الاثنين   │ لا شيء — حركة طبيعية فقط                              │
    │ الثلاثاء  │ تخمين كلمات مرور FTP و SSH (Patator)                   │
    │ الأربعاء  │ DoS: Hulk, GoldenEye, Slowloris, Slowhttptest + Heartbleed │
    │ الخميس    │ هجمات ويب (Brute Force, XSS, SQL Injection) + اختراق داخلي │
    │ الجمعة    │ Botnet (Ares) + PortScan (nmap) + DDoS (LOIC)          │
    └───────────┴──────────────────────────────────────────────────────┘

هذا الترتيب الزمني يسمح بتجربة واقعية جداً: ندرّب على الاثنين–الأربعاء ونختبر
على الخميس–الجمعة ← كل هجمات الاختبار من أنواع لم يرها النموذج (Zero-day حقيقي).
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd

from netsentinel.data.schema import NORMAL_LABEL
from netsentinel.data.spec import DatasetSpec

logger = logging.getLogger(__name__)

CICIDS_DIR = "cicids2017"
CSV_SUBDIR = "MachineLearningCVE"
CICIDS_ZIP_URL = "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/csvs/MachineLearningCSV.zip"
CICIDS_ZIP_SHA256 = "c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928"

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

# أعمدة نحذفها، ولماذا:
DROPPED_COLUMNS = {
    # المنفذ رقم وليس سلوكاً: لو أبقيناه سيتعلّم النموذج "المنفذ 80 يوم الأربعاء = DoS"
    # بدل أن يتعلّم شكل الهجوم. حذفه يجبره على تعلّم السلوك.
    "Destination Port": "shortcut",
    # عمود مكرّر حرفياً من خطأ في CICFlowMeter
    "Fwd Header Length.1": "duplicate",
    # أعمدة قيمتها صفر في كل السجلات الـ 2.8 مليون ← لا معلومة فيها
    "Bwd PSH Flags": "constant", "Bwd URG Flags": "constant",
    "Fwd Avg Bytes/Bulk": "constant", "Fwd Avg Packets/Bulk": "constant", "Fwd Avg Bulk Rate": "constant",
    "Bwd Avg Bytes/Bulk": "constant", "Bwd Avg Packets/Bulk": "constant", "Bwd Avg Bulk Rate": "constant",
}

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

FEATURE_DESCRIPTIONS_AR = {
    "Flow Duration": "مدة التدفّق (ميكروثانية)",
    "Total Fwd Packets": "عدد الحزم من المُبادِر",
    "Total Backward Packets": "عدد الحزم من المستجيب",
    "Total Length of Fwd Packets": "مجموع بايتات حزم المُبادِر",
    "Total Length of Bwd Packets": "مجموع بايتات حزم المستجيب",
    "Fwd Packet Length Max": "أكبر حزمة من المُبادِر",
    "Fwd Packet Length Min": "أصغر حزمة من المُبادِر",
    "Fwd Packet Length Mean": "متوسط حجم حزم المُبادِر",
    "Fwd Packet Length Std": "تشتّت أحجام حزم المُبادِر",
    "Bwd Packet Length Max": "أكبر حزمة من المستجيب",
    "Bwd Packet Length Min": "أصغر حزمة من المستجيب",
    "Bwd Packet Length Mean": "متوسط حجم حزم المستجيب",
    "Bwd Packet Length Std": "تشتّت أحجام حزم المستجيب",
    "Flow Bytes/s": "معدّل البايتات في الثانية",
    "Flow Packets/s": "معدّل الحزم في الثانية",
    "Flow IAT Mean": "متوسط الزمن بين الحزم",
    "Flow IAT Std": "تشتّت الزمن بين الحزم",
    "Flow IAT Max": "أطول فجوة زمنية بين حزمتين",
    "Flow IAT Min": "أقصر فجوة زمنية بين حزمتين",
    "Fwd IAT Total": "مجموع الفجوات بين حزم المُبادِر",
    "Fwd IAT Mean": "متوسط الفجوة بين حزم المُبادِر",
    "Fwd IAT Std": "تشتّت الفجوات بين حزم المُبادِر",
    "Fwd IAT Max": "أطول فجوة بين حزم المُبادِر",
    "Fwd IAT Min": "أقصر فجوة بين حزم المُبادِر",
    "Bwd IAT Total": "مجموع الفجوات بين حزم المستجيب",
    "Bwd IAT Mean": "متوسط الفجوة بين حزم المستجيب",
    "Bwd IAT Std": "تشتّت الفجوات بين حزم المستجيب",
    "Bwd IAT Max": "أطول فجوة بين حزم المستجيب",
    "Bwd IAT Min": "أقصر فجوة بين حزم المستجيب",
    "Fwd PSH Flags": "عدد أعلام PSH من المُبادِر",
    "Fwd URG Flags": "عدد أعلام URG من المُبادِر",
    "Fwd Header Length": "مجموع أطوال الترويسات من المُبادِر",
    "Bwd Header Length": "مجموع أطوال الترويسات من المستجيب",
    "Fwd Packets/s": "معدّل حزم المُبادِر في الثانية",
    "Bwd Packets/s": "معدّل حزم المستجيب في الثانية",
    "Min Packet Length": "أصغر حزمة في التدفّق",
    "Max Packet Length": "أكبر حزمة في التدفّق",
    "Packet Length Mean": "متوسط حجم الحزمة",
    "Packet Length Std": "الانحراف المعياري لحجم الحزمة",
    "Packet Length Variance": "تباين حجم الحزمة",
    "FIN Flag Count": "عدد حزم FIN (إنهاء)",
    "SYN Flag Count": "عدد حزم SYN (بدء اتصال)",
    "RST Flag Count": "عدد حزم RST (قطع)",
    "PSH Flag Count": "عدد حزم PSH",
    "ACK Flag Count": "عدد حزم ACK",
    "URG Flag Count": "عدد حزم URG",
    "CWE Flag Count": "عدد حزم CWR",
    "ECE Flag Count": "عدد حزم ECE (ازدحام)",
    "Down/Up Ratio": "نسبة التنزيل إلى الرفع",
    "Average Packet Size": "متوسط حجم الحزمة",
    "Avg Fwd Segment Size": "متوسط حجم مقطع المُبادِر",
    "Avg Bwd Segment Size": "متوسط حجم مقطع المستجيب",
    "Subflow Fwd Packets": "حزم المُبادِر في التدفّق الفرعي",
    "Subflow Fwd Bytes": "بايتات المُبادِر في التدفّق الفرعي",
    "Subflow Bwd Packets": "حزم المستجيب في التدفّق الفرعي",
    "Subflow Bwd Bytes": "بايتات المستجيب في التدفّق الفرعي",
    "Init_Win_bytes_forward": "حجم نافذة TCP الأولى للمُبادِر",
    "Init_Win_bytes_backward": "حجم نافذة TCP الأولى للمستجيب",
    "act_data_pkt_fwd": "حزم المُبادِر التي تحمل بيانات فعلية",
    "min_seg_size_forward": "أصغر حجم مقطع من المُبادِر",
    "Active Mean": "متوسط فترات النشاط",
    "Active Std": "تشتّت فترات النشاط",
    "Active Max": "أطول فترة نشاط",
    "Active Min": "أقصر فترة نشاط",
    "Idle Mean": "متوسط فترات الخمول",
    "Idle Std": "تشتّت فترات الخمول",
    "Idle Max": "أطول فترة خمول",
    "Idle Min": "أقصر فترة خمول",
}


def cicids_dir(raw_dir: Path) -> Path:
    return raw_dir / CICIDS_DIR


def download_cicids(raw_dir: Path, force: bool = False) -> None:
    """ينزّل ملف CSV الأصلي (235 MB)، يتحقّق من SHA-256، ثم يفكّ الضغط."""
    import hashlib
    import urllib.request
    import zipfile

    target_dir = cicids_dir(raw_dir)
    if (target_dir / CSV_SUBDIR).exists() and not force:
        logger.info("✓ CIC-IDS2017 موجودة مسبقاً")
        return
    target_dir.mkdir(parents=True, exist_ok=True)
    archive = target_dir / "MachineLearningCSV.zip"
    logger.info("↓ تنزيل CIC-IDS2017 (235 MB) ...")
    urllib.request.urlretrieve(CICIDS_ZIP_URL, archive)

    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    if sha != CICIDS_ZIP_SHA256:
        archive.unlink()
        raise ValueError(f"SHA-256 mismatch — الملف تالف أو معدَّل: {sha}")
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(target_dir)
    logger.info("✓ تم التحقّق من سلامة الملف وفكّ الضغط")


def _clean_label(label: str) -> str:
    """يصلح ترميز الحرف المكسور في أسماء هجمات الويب: 'Web Attack � XSS' ← 'Web Attack - XSS'."""
    label = label.strip()
    for broken in ("�", "ï¿½", "�"):
        label = label.replace(broken, "-")
    return " ".join(label.split())


def load_cicids(raw_dir: Path, days: list[str] | None = None) -> pd.DataFrame:
    """
    يحمّل أياماً من CIC-IDS2017 وينظّفها:
        1. توحيد أسماء الأعمدة (إزالة المسافات الزائدة).
        2. حذف الأعمدة المذكورة في DROPPED_COLUMNS.
        3. حذف السطور التي فيها Infinity أو NaN (قسمة على صفر داخل CICFlowMeter).
        4. حذف السطور المكرّرة حرفياً (~10% من البيانات!) — وإلا قد يظهر نفس
           السجل في التدريب والاختبار فتنتفخ النتائج.
    ويضيف: attack, category, is_attack, day.

    النتيجة تُخزَّن مؤقتاً (cache) لأن قراءة 900 MB من CSV تأخذ وقتاً.
    """
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
                raise FileNotFoundError(f"{path} غير موجود — شغّل: netsentinel download --dataset cicids2017")
            df = pd.read_csv(path, encoding="latin-1", low_memory=False)
            df.columns = df.columns.str.strip()
            df["day"] = day
            frames.append(df)
            logger.info("حُمّل %s: %d تدفّق", filename, len(df))

    df = pd.concat(frames, ignore_index=True).drop(columns=list(DROPPED_COLUMNS))
    df["attack"] = df.pop("Label").map(_clean_label)
    features = cicids_features()
    df[features] = df[features].astype(np.float64).replace([np.inf, -np.inf], np.nan)

    before = len(df)
    df = df.dropna(subset=features)
    n_invalid = before - len(df)
    df = df.drop_duplicates(subset=features + ["attack"])
    logger.info("التنظيف: حُذف %d سطر غير صالح (Inf/NaN) و %d سطر مكرّر ← بقي %d",
                n_invalid, before - n_invalid - len(df), len(df))

    df[features] = df[features].astype(np.float32)     # نصف الذاكرة
    df["category"] = df["attack"].map(ATTACK_CATEGORY)
    if df["category"].isna().any():
        raise ValueError(f"Unknown labels: {df.loc[df['category'].isna(), 'attack'].unique()}")
    df["is_attack"] = (df["category"] != NORMAL_LABEL).astype(int)
    df = df.reset_index(drop=True)
    df.to_pickle(cache)
    return df


def cicids_features() -> list[str]:
    """الأعمدة الـ 68 التي يتدرّب عليها النموذج (78 عموداً أصلياً − 10 محذوفة)."""
    return [c for c in FEATURE_DESCRIPTIONS_AR if c not in DROPPED_COLUMNS]


def cicids_spec(profile: str) -> DatasetSpec:
    features = cicids_features()
    return DatasetSpec(
        name="CIC-IDS2017",
        profile=profile,
        features=features,
        categorical=[],
        skewed=features,               # كل ميزات CICFlowMeter بذيل طويل جداً
        class_names=CLASS_NAMES,
        descriptions=FEATURE_DESCRIPTIONS_AR,
    )
