"""
خطّ التدريب الكامل (End-to-End Training Pipeline) — يعمل على أي مجموعة بيانات.

لكل تجربة ننفّذ:

    ① تقسيم بيانات التدريب إلى تدريب (80%) وتحقق (20%) — تقسيم طبقي (Stratified)
       حتى تبقى نسب الفئات النادرة نفسها في الجزأين.
    ② تدريب المعالجة المسبقة على جزء التدريب فقط.
    ③ تدريب كل المصنِّفات المرشّحة ← اختيار الأفضل حسب Macro-F1 على التحقق.
    ④ تدريب كواشف الشذوذ على "الطبيعي" فقط ← معايرة العتبة على طبيعي التحقق
       ← اختيار الأفضل حسب ROC-AUC.
    ⑤ تجميع النظام الهجين وحفظه.
    ⑥ التقييم على مجموعات الاختبار (بيانات لم يرها النظام إطلاقاً)
       + رسوم + أهمية الميزات.

القاعدة الذهبية: مجموعة الاختبار لا تُستخدم أبداً في أي قرار (اختيار نموذج،
عتبة...). تُستخدم مرة واحدة في النهاية فقط ← نتائج صادقة غير متحيّزة.

هذا الملف يحوي الخطوات العامة + تجربة NSL-KDD. تجارب CIC-IDS2017 في
pipeline/cicids_experiments.py وتستخدم نفس الدوال.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split

from netsentinel.config import Config
from netsentinel.data.loader import load_split, mark_novel_attacks
from netsentinel.data.schema import NORMAL_LABEL
from netsentinel.data.spec import DatasetSpec, nsl_kdd_spec
from netsentinel.evaluation import plots
from netsentinel.evaluation.metrics import attack_score, binary_metrics, evaluate_hybrid, multiclass_metrics
from netsentinel.explain.importance import compute_permutation_importance
from netsentinel.features.preprocessing import build_preprocessor, select_features
from netsentinel.models.anomaly import build_detector
from netsentinel.models.hybrid import HybridIDS, NormalBaseline
from netsentinel.models.supervised import build_classifier

logger = logging.getLogger(__name__)

# النسب المئوية التي نجرّبها في تحليل حساسية العتبة (95 = عتبة منخفضة، 99.99 = مرتفعة جداً)
SENSITIVITY_PERCENTILES = [95.0, 99.0, 99.5, 99.9, 99.99]


def model_path(cfg: Config, run: str) -> Path:
    """مسار النموذج المحفوظ لتجربة: artifacts/<run>/hybrid_ids.joblib"""
    return cfg.paths.artifacts_dir / run / "hybrid_ids.joblib"


def _select_classifier(cfg, X_tr, y_tr, X_val, y_val, class_names) -> tuple[object, pd.DataFrame]:
    """③ يدرّب كل مصنِّف مرشّح ويُرجع الأفضل + جدول المقارنة."""
    rows, fitted = {}, {}
    for name in cfg.supervised.candidates:
        start = time.perf_counter()
        clf = build_classifier(name, cfg.seed).fit(X_tr, y_tr)
        pred = clf.predict(X_val)
        multi = multiclass_metrics(y_val, pred, class_names)
        binary = binary_metrics((y_val != NORMAL_LABEL).astype(int), (pred != NORMAL_LABEL).astype(int))
        rows[name] = {
            "f1_macro": multi["f1_macro"],
            "accuracy": multi["accuracy"],
            "detection_rate": binary["detection_rate"],
            "false_alarm_rate": binary["false_alarm_rate"],
            "train_seconds": round(time.perf_counter() - start, 1),
        }
        fitted[name] = clf
        logger.info("  %-24s Macro-F1=%.4f  DR=%.4f  FAR=%.4f  (%.1fs)", name, multi["f1_macro"],
                    binary["detection_rate"], binary["false_alarm_rate"], rows[name]["train_seconds"])

    table = pd.DataFrame(rows).T
    best = table[cfg.supervised.selection_metric].astype(float).idxmax()
    logger.info("  ★ أفضل مصنِّف: %s", best)
    return fitted[best], table


def _select_detector(cfg, X_tr_normal, X_val, y_val_attack) -> tuple[object, pd.DataFrame]:
    """④ يدرّب كواشف الشذوذ على الطبيعي فقط ويختار الأفضل حسب ROC-AUC."""
    rows, fitted = {}, {}
    X_val_normal = X_val[y_val_attack == 0]
    for name in cfg.anomaly.candidates:
        start = time.perf_counter()
        det = build_detector(name, cfg.seed).fit(X_tr_normal)
        det.calibrate(X_val_normal, cfg.anomaly.threshold_percentile)
        scores = det.score(X_val)
        binary = binary_metrics(y_val_attack, (scores > det.threshold_).astype(int))
        rows[name] = {
            "roc_auc": round(float(roc_auc_score(y_val_attack, scores)), 4),
            "detection_rate": binary["detection_rate"],
            "false_alarm_rate": binary["false_alarm_rate"],
            "threshold": round(det.threshold_, 6),
            "train_seconds": round(time.perf_counter() - start, 1),
        }
        fitted[name] = det
        logger.info("  %-24s ROC-AUC=%.4f  DR=%.4f  FAR=%.4f  (%.1fs)", name, rows[name]["roc_auc"],
                    binary["detection_rate"], binary["false_alarm_rate"], rows[name]["train_seconds"])

    table = pd.DataFrame(rows).T
    best = table["roc_auc"].astype(float).idxmax()
    logger.info("  ★ أفضل كاشف شذوذ: %s", best)
    return fitted[best], table


def train_hybrid(cfg: Config, spec: DatasetSpec, train_df: pd.DataFrame, run: str) -> tuple[HybridIDS, dict]:
    """①–⑤ تدريب نظام هجين كامل على train_df وحفظه في artifacts/<run>/."""
    logger.info("═══ تدريب: %s / %s ═══", spec.name, run)
    tr, val = train_test_split(
        train_df, test_size=cfg.data.validation_size, stratify=train_df["category"], random_state=cfg.seed,
    )

    preprocessor = build_preprocessor(spec)
    X_tr = preprocessor.fit_transform(select_features(tr, spec))
    X_val = preprocessor.transform(select_features(val, spec))
    logger.info("التدريب: %d سجل — التحقق: %d — أبعاد بعد المعالجة: %d", len(tr), len(val), X_tr.shape[1])

    logger.info("── المصنِّفات المُشرَفة ──")
    classifier, clf_table = _select_classifier(cfg, X_tr, tr["category"], X_val, val["category"], spec.class_names)

    logger.info("── كواشف الشذوذ (تدريب على الطبيعي فقط) ──")
    tr_normal = (tr["is_attack"] == 0).to_numpy()
    detector, det_table = _select_detector(cfg, X_tr[tr_normal], X_val, val["is_attack"].to_numpy())
    # نحفظ عتبات بديلة محسوبة من طبيعي التحقق (لا من الاختبار) لتحليل الحساسية لاحقاً
    val_normal_scores = detector.score(X_val[(val["is_attack"] == 0).to_numpy()])
    candidate_thresholds = {str(p): float(np.percentile(val_normal_scores, p)) for p in SENSITIVITY_PERCENTILES}

    model = HybridIDS(
        spec=spec,
        preprocessor=preprocessor,
        classifier=classifier,
        detector=detector,
        baseline=NormalBaseline.from_frame(select_features(tr[tr["is_attack"] == 0], spec), spec),
        metadata={
            "dataset": spec.name,
            "run": run,
            "classifier": clf_table[cfg.supervised.selection_metric].astype(float).idxmax(),
            "detector": det_table["roc_auc"].astype(float).idxmax(),
            "threshold_percentile": cfg.anomaly.threshold_percentile,
            "candidate_thresholds": candidate_thresholds,
            "n_train": len(tr), "n_validation": len(val),
            "n_features": len(spec.features),
            "n_encoded_features": int(X_tr.shape[1]),
            "train_classes": sorted(train_df["category"].unique().tolist()),
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "baseline_source": spec.name,
        },
    )
    model.save(model_path(cfg, run))
    return model, {"classifier_comparison": clf_table, "detector_comparison": det_table}


def evaluate_model(
    cfg: Config, model: HybridIDS, run: str, selection: dict, test_sets: dict[str, pd.DataFrame],
) -> dict:
    """⑥ التقييم النهائي على كل مجموعة اختبار + الرسوم + أهمية الميزات + metrics.json."""
    spec = model.spec
    out_dir = cfg.paths.reports_dir / run
    fig_dir = out_dir / "figures"
    results: dict = {
        "run": run,
        "profile": run,
        "dataset": spec.name,
        "metadata": model.metadata,
        "validation": {k: v.to_dict(orient="index") for k, v in selection.items()},
        "test": {},
    }
    plots.plot_model_comparison(
        selection["classifier_comparison"][["f1_macro", "accuracy", "detection_rate"]].astype(float),
        fig_dir / "model_comparison.png",
    )

    for split, test_df in test_sets.items():
        start = time.perf_counter()
        pred = model.predict(test_df)
        metrics = evaluate_hybrid(test_df, pred, spec.class_names)
        results["test"][split] = metrics
        h, c = metrics["hybrid"], metrics["classifier_only"]
        logger.info("[%s] Hybrid: DR=%.4f FAR=%.4f F1=%.4f | Classifier: DR=%.4f FAR=%.4f  (%d سجل، %.0fs)",
                    split, h["detection_rate"], h["false_alarm_rate"], h["f1"],
                    c["detection_rate"], c["false_alarm_rate"], len(test_df), time.perf_counter() - start)

        tag = split.replace("+", "plus")
        plots.plot_confusion_matrix(test_df["category"], pred["classifier_label"], fig_dir / f"confusion_{tag}.png",
                                    f"Confusion matrix — {split} ({run})", spec.class_names)
        plots.plot_roc_curves(
            test_df["is_attack"].to_numpy(),
            {"Classifier": attack_score(pred), "Anomaly detector": pred["anomaly_score"].to_numpy()},
            fig_dir / f"roc_{tag}.png", f"ROC — {split} ({run})",
        )
        plots.plot_anomaly_scores(pred["anomaly_score"].to_numpy(), test_df["is_attack"].to_numpy(),
                                  model.detector.threshold_, fig_dir / f"anomaly_scores_{tag}.png")
        if "novel_attacks" in metrics:
            plots.plot_novel_detection(metrics["novel_attacks"], fig_dir / f"novel_detection_{tag}.png")
        metrics["threshold_sensitivity"] = threshold_sensitivity(model, test_df, pred)
        plots.plot_threshold_sensitivity(metrics["threshold_sensitivity"], fig_dir / f"threshold_sensitivity_{tag}.png")

    logger.info("حساب أهمية الميزات (Permutation Importance)...")
    first_test = next(iter(test_sets.values()))
    importance = compute_permutation_importance(
        model, first_test, cfg.evaluation.permutation_importance_samples, cfg.seed)
    results["feature_importance"] = importance.round(5).to_dict()
    plots.plot_feature_importance(importance, fig_dir / "feature_importance.png")

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False, default=_json_default), encoding="utf-8")
    return results


def threshold_sensitivity(model: HybridIDS, test_df: pd.DataFrame, pred: pd.DataFrame) -> list[dict]:
    """
    تحليل حساسية العتبة: كيف يتغيّر الكشف والإنذار الكاذب للنظام الهجين لو
    اخترنا عتبة أخرى؟ كل العتبات محسوبة من طبيعي التحقق وقت التدريب، فهذا
    التحليل يعرض "منحنى التشغيل" دون أن نختار شيئاً بناءً على الاختبار.
    """
    y = test_df["is_attack"].to_numpy()
    clf_alert = pred["classifier_label"].to_numpy() != NORMAL_LABEL
    novel = test_df["is_novel"].to_numpy() == 1 if "is_novel" in test_df.columns else np.zeros(len(y), bool)
    rows = []
    for pct, thr in model.metadata.get("candidate_thresholds", {}).items():
        alert = (clf_alert | (pred["anomaly_score"].to_numpy() > thr)).astype(int)
        m = binary_metrics(y, alert)
        rows.append({
            "percentile": float(pct), "threshold": round(thr, 6),
            "detection_rate": m["detection_rate"], "false_alarm_rate": m["false_alarm_rate"],
            "precision": m["precision"], "f1": m["f1"],
            "novel_dr": round(float(alert[novel].mean()), 4) if novel.any() else None,
        })
    return rows


def _json_default(obj):
    if isinstance(obj, (np.integer, np.floating)):
        return obj.item()
    raise TypeError(type(obj))


def run_training(cfg: Config, profiles: list[str] | None = None) -> dict[str, dict]:
    """تجربة NSL-KDD: يدرّب ويقيّم ملفّي الميزات full و live ويولّد RESULTS.md."""
    from netsentinel.pipeline.report import write_report

    np.random.seed(cfg.seed)
    train_df = load_split(cfg.paths.raw_dir, "KDDTrain+")
    test_sets = {
        split: mark_novel_attacks(load_split(cfg.paths.raw_dir, split), train_df)
        for split in cfg.evaluation.test_sets
    }
    all_results = {}
    for profile in profiles or cfg.data.feature_profiles:
        model, selection = train_hybrid(cfg, nsl_kdd_spec(profile), train_df, run=profile)
        all_results[profile] = evaluate_model(cfg, model, profile, selection, test_sets)
    report = write_report(cfg, all_results, "RESULTS.md", "تقرير نتائج NetSentinel — NSL-KDD")
    logger.info("✓ اكتمل. التقرير: %s", report)
    return all_results
