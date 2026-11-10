"""
تجارب CIC-IDS2017 — اختبار النظام على حركة شبكة حقيقية حديثة (2017).

نجري تجربتين، والمقارنة بينهما هي الرسالة البحثية:

    ① التقسيم العشوائي (random) — "الطريقة الشائعة في الأبحاث"
       نخلط الأيام الخمسة ونأخذ 30% عشوائياً للاختبار.
       ← كل نوع هجوم في الاختبار رآه النموذج في التدريب ← أرقام شبه مثالية (~99%).
       لكنها لا تجيب عن السؤال الأمني الحقيقي.

    ② التقسيم الزمني (temporal) — "محاكاة الواقع"
       ندرّب على الاثنين–الأربعاء فقط، ونختبر على الخميس–الجمعة.
       ← هجمات الاختبار (Web, Infiltration, Bot, PortScan, DDoS) لم يرَ النموذج
         أياً منها ← هذا بالضبط موقف نظام حقيقي يوم يأتيه هجوم جديد.

عيّنة التدريب: بيانات CIC كبيرة جداً (2.5 مليون تدفّق بعد التنظيف). ندرّب على
عيّنة متوازنة (250 ألف طبيعي + حتى 50 ألفاً من كل نوع هجوم) — هذا يسرّع التدريب
ويمنع طغيان الفئات الكبيرة (DoS Hulk = 170 ألفاً) على النادرة (Heartbleed = 11).
أما الاختبار فيكون على كامل البيانات المخصّصة له دون أي اختزال.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from netsentinel.config import Config
from netsentinel.data.cicids import cicids_spec, load_cicids
from netsentinel.data.loader import mark_novel_attacks
from netsentinel.pipeline.train import evaluate_model, train_hybrid

logger = logging.getLogger(__name__)

TRAIN_DAYS = ["monday", "tuesday", "wednesday"]
TEST_DAYS = ["thursday", "friday"]


def balanced_sample(df: pd.DataFrame, normal_n: int, attack_cap: int, seed: int) -> pd.DataFrame:
    """عيّنة تدريب: normal_n سجلاً طبيعياً + حتى attack_cap سجلاً من كل نوع هجوم (كل النادر يُؤخذ كاملاً)."""
    normal = df[df["is_attack"] == 0]
    parts = [normal.sample(n=min(normal_n, len(normal)), random_state=seed)]
    for _, group in df[df["is_attack"] == 1].groupby("attack"):
        parts.append(group.sample(n=min(attack_cap, len(group)), random_state=seed))
    return pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)


def _run(cfg: Config, run: str, train_pool: pd.DataFrame, test_df: pd.DataFrame) -> dict:
    c = cfg.cicids
    train_df = balanced_sample(train_pool, c.normal_train_samples, c.attack_cap_per_type, cfg.seed)
    logger.info("[%s] عيّنة التدريب: %s", run, train_df["attack"].value_counts().to_dict())
    test_df = mark_novel_attacks(test_df, train_df)
    model, selection = train_hybrid(cfg, cicids_spec(run), train_df, run)
    return evaluate_model(cfg, model, run, selection, {"test": test_df})


def run_random_split(cfg: Config, data: pd.DataFrame) -> dict:
    """① كل الأيام مختلطة، 30% اختبار (طبقي حسب نوع الهجوم)."""
    pool, test = train_test_split(
        data, test_size=cfg.cicids.random_test_size, stratify=data["attack"], random_state=cfg.seed)
    return _run(cfg, "cicids2017_random", pool, test)


def run_temporal_split(cfg: Config, data: pd.DataFrame) -> dict:
    """② تدريب على الاثنين–الأربعاء، اختبار على الخميس–الجمعة كاملين."""
    pool = data[data["day"].isin(TRAIN_DAYS)]
    test = data[data["day"].isin(TEST_DAYS)]
    return _run(cfg, "cicids2017_temporal", pool, test)


def run_cicids(cfg: Config, experiments: list[str] | None = None) -> dict[str, dict]:
    from netsentinel.pipeline.report import write_report

    np.random.seed(cfg.seed)
    data = load_cicids(cfg.paths.raw_dir)
    logger.info("CIC-IDS2017 بعد التنظيف: %d تدفّق — %s", len(data), data["category"].value_counts().to_dict())

    runners = {"random": run_random_split, "temporal": run_temporal_split}
    results = {}
    for name in experiments or list(runners):
        res = runners[name](cfg, data)
        results[res["run"]] = res
    report = write_report(cfg, results, "RESULTS_CICIDS2017.md", "تقرير نتائج NetSentinel — CIC-IDS2017 (حركة حقيقية)")
    logger.info("✓ اكتمل. التقرير: %s", report)
    return results
