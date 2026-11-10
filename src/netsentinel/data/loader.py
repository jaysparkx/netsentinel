"""
تنزيل وتحميل مجموعة بيانات NSL-KDD.

NSL-KDD هي نسخة محسّنة من KDD Cup 99 (المعهد الكندي للأمن السيبراني):
    - أُزيلت السجلّات المكرّرة التي كانت تجعل النماذج "تحفظ" بدل أن "تتعلّم".
    - ملف الاختبار KDDTest+ يحتوي هجمات غير موجودة في التدريب (17 نوعاً)،
      وهذا يجعله اختباراً حقيقياً لقدرة النظام على كشف الهجمات الجديدة.
    - KDDTest-21 = السجلّات الصعبة فقط (التي أخطأ فيها أغلب المصنِّفات المرجعية).
"""

from __future__ import annotations

import logging
import urllib.request
from pathlib import Path

import pandas as pd

from netsentinel.data.schema import NORMAL_LABEL, RAW_COLUMNS, attack_to_category

logger = logging.getLogger(__name__)

# مرآة عامة لملفات NSL-KDD الأصلية
NSL_KDD_BASE_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
NSL_KDD_FILES = {
    "KDDTrain+": "KDDTrain+.txt",
    "KDDTest+": "KDDTest+.txt",
    "KDDTest-21": "KDDTest-21.txt",
}


def download_nsl_kdd(raw_dir: Path, force: bool = False) -> None:
    """ينزّل ملفات NSL-KDD الثلاثة إلى raw_dir (يتخطّى الموجود مسبقاً)."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    for name, filename in NSL_KDD_FILES.items():
        target = raw_dir / filename
        if target.exists() and not force:
            logger.info("✓ %s موجود مسبقاً", filename)
            continue
        logger.info("↓ تنزيل %s ...", filename)
        urllib.request.urlretrieve(NSL_KDD_BASE_URL + filename, target)


def load_split(raw_dir: Path, split: str) -> pd.DataFrame:
    """
    يحمّل ملفاً واحداً (مثل "KDDTrain+") ويضيف أعمدة التسميات المشتقّة:

        attack     : اسم الهجوم الأصلي (neptune, smurf, normal ...)
        category   : الفئة (normal / DoS / Probe / R2L / U2R)  ← هدف التصنيف المتعدّد
        is_attack  : 0 أو 1                                     ← هدف التصنيف الثنائي
    """
    path = raw_dir / NSL_KDD_FILES[split]
    if not path.exists():
        raise FileNotFoundError(f"{path} غير موجود — شغّل أولاً: netsentinel download")

    df = pd.read_csv(path, header=None, names=RAW_COLUMNS)
    df["attack"] = df["attack"].str.strip()
    df["category"] = df["attack"].map(attack_to_category)
    df["is_attack"] = (df["attack"] != NORMAL_LABEL).astype(int)
    logger.info("حُمّل %s: %d سجلّ", split, len(df))
    return df


def mark_novel_attacks(test_df: pd.DataFrame, train_df: pd.DataFrame) -> pd.DataFrame:
    """
    يضيف عمود is_novel = 1 للهجمات الموجودة في الاختبار وغير الموجودة في التدريب.

    هذا العمود هو مفتاح التجربة البحثية: نقيس عليه قدرة النظام على كشف
    هجمات "لم يرها من قبل" — وهي محاكاة واقعية لهجمات Zero-day.
    """
    known = set(train_df["attack"].unique())
    test_df = test_df.copy()
    test_df["is_novel"] = (~test_df["attack"].isin(known)).astype(int)
    return test_df
