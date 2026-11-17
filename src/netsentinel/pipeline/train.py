import json
import logging
import time

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split

from netsentinel.data.loader import load_split, mark_novel_attacks
from netsentinel.data.schema import NORMAL_LABEL
from netsentinel.data.spec import nsl_kdd_spec
from netsentinel.evaluation import plots
from netsentinel.evaluation.metrics import attack_score, binary_metrics, evaluate_hybrid, multiclass_metrics
from netsentinel.explain.importance import compute_permutation_importance
from netsentinel.features.preprocessing import build_preprocessor, select_features
from netsentinel.models.anomaly import build_detector
from netsentinel.models.hybrid import HybridIDS, NormalBaseline
from netsentinel.models.supervised import build_classifier

logger = logging.getLogger(__name__)

# other thresholds we try after training (percentiles of normal validation scores)
SENSITIVITY_PERCENTILES = [95.0, 99.0, 99.5, 99.9, 99.99]


def model_path(cfg, run):
    return cfg.paths.artifacts_dir / run / "hybrid_ids.joblib"


def pick_classifier(cfg, X_tr, y_tr, X_val, y_val, class_names):
    """Train every candidate classifier, keep the best one by macro-F1 on validation."""
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
        logger.info("  %-24s f1=%.4f dr=%.4f far=%.4f (%.1fs)", name, multi["f1_macro"],
                    binary["detection_rate"], binary["false_alarm_rate"], rows[name]["train_seconds"])

    table = pd.DataFrame(rows).T
    best = table[cfg.supervised.selection_metric].astype(float).idxmax()
    logger.info("  best classifier: %s", best)
    return fitted[best], table


def pick_detector(cfg, X_tr_normal, X_val, y_val_attack):
    """Train anomaly detectors on normal rows only, keep the best one by ROC-AUC."""
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
        logger.info("  %-24s auc=%.4f dr=%.4f far=%.4f (%.1fs)", name, rows[name]["roc_auc"],
                    binary["detection_rate"], binary["false_alarm_rate"], rows[name]["train_seconds"])

    table = pd.DataFrame(rows).T
    best = table["roc_auc"].astype(float).idxmax()
    logger.info("  best detector: %s", best)
    return fitted[best], table


def train_hybrid(cfg, spec, train_df, run):
    logger.info("training %s / %s", spec.name, run)
    tr, val = train_test_split(train_df, test_size=cfg.data.validation_size,
                               stratify=train_df["category"], random_state=cfg.seed)

    preprocessor = build_preprocessor(spec)
    X_tr = preprocessor.fit_transform(select_features(tr, spec))
    X_val = preprocessor.transform(select_features(val, spec))
    logger.info("train %d, validation %d, %d columns after encoding", len(tr), len(val), X_tr.shape[1])

    classifier, clf_table = pick_classifier(cfg, X_tr, tr["category"], X_val, val["category"], spec.class_names)

    tr_normal = (tr["is_attack"] == 0).to_numpy()
    detector, det_table = pick_detector(cfg, X_tr[tr_normal], X_val, val["is_attack"].to_numpy())

    # extra thresholds from validation data, used later for the threshold table
    val_normal_scores = detector.score(X_val[(val["is_attack"] == 0).to_numpy()])
    thresholds = {str(p): float(np.percentile(val_normal_scores, p)) for p in SENSITIVITY_PERCENTILES}

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
            "candidate_thresholds": thresholds,
            "n_train": len(tr),
            "n_validation": len(val),
            "n_features": len(spec.features),
            "n_encoded_features": int(X_tr.shape[1]),
            "train_classes": sorted(train_df["category"].unique().tolist()),
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "baseline_source": spec.name,
        },
    )
    model.save(model_path(cfg, run))
    return model, {"classifier_comparison": clf_table, "detector_comparison": det_table}


def threshold_sensitivity(model, test_df, pred):
    y = test_df["is_attack"].to_numpy()
    clf_alert = pred["classifier_label"].to_numpy() != NORMAL_LABEL
    if "is_novel" in test_df.columns:
        novel = test_df["is_novel"].to_numpy() == 1
    else:
        novel = np.zeros(len(y), bool)

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


def evaluate_model(cfg, model, run, selection, test_sets):
    spec = model.spec
    out_dir = cfg.paths.reports_dir / run
    fig_dir = out_dir / "figures"
    results = {
        "run": run,
        "profile": run,
        "dataset": spec.name,
        "metadata": model.metadata,
        "validation": {k: v.to_dict(orient="index") for k, v in selection.items()},
        "test": {},
    }
    comparison = selection["classifier_comparison"][["f1_macro", "accuracy", "detection_rate"]].astype(float)
    plots.plot_model_comparison(comparison, fig_dir / "model_comparison.png")

    for split, test_df in test_sets.items():
        pred = model.predict(test_df)
        metrics = evaluate_hybrid(test_df, pred, spec.class_names)
        results["test"][split] = metrics
        h, c = metrics["hybrid"], metrics["classifier_only"]
        logger.info("[%s] hybrid dr=%.4f far=%.4f | classifier dr=%.4f far=%.4f", split,
                    h["detection_rate"], h["false_alarm_rate"], c["detection_rate"], c["false_alarm_rate"])

        tag = split.replace("+", "plus")
        plots.plot_confusion_matrix(test_df["category"], pred["classifier_label"],
                                    fig_dir / f"confusion_{tag}.png", f"Confusion matrix - {split} ({run})",
                                    spec.class_names)
        scores = {"Classifier": attack_score(pred), "Anomaly detector": pred["anomaly_score"].to_numpy()}
        plots.plot_roc_curves(test_df["is_attack"].to_numpy(), scores, fig_dir / f"roc_{tag}.png",
                              f"ROC - {split} ({run})")
        plots.plot_anomaly_scores(pred["anomaly_score"].to_numpy(), test_df["is_attack"].to_numpy(),
                                  model.detector.threshold_, fig_dir / f"anomaly_scores_{tag}.png")
        if "novel_attacks" in metrics:
            plots.plot_novel_detection(metrics["novel_attacks"], fig_dir / f"novel_detection_{tag}.png")
        metrics["threshold_sensitivity"] = threshold_sensitivity(model, test_df, pred)
        plots.plot_threshold_sensitivity(metrics["threshold_sensitivity"], fig_dir / f"threshold_sensitivity_{tag}.png")

    logger.info("permutation importance...")
    first_test = next(iter(test_sets.values()))
    importance = compute_permutation_importance(model, first_test, cfg.evaluation.permutation_importance_samples,
                                                cfg.seed)
    results["feature_importance"] = importance.round(5).to_dict()
    plots.plot_feature_importance(importance, fig_dir / "feature_importance.png")

    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=_to_python)
    return results


def _to_python(obj):
    if isinstance(obj, (np.integer, np.floating)):
        return obj.item()
    raise TypeError(type(obj))


def run_training(cfg, profiles=None):
    """NSL-KDD experiment: train the full and live profiles and write RESULTS.md."""
    from netsentinel.pipeline.report import write_report

    np.random.seed(cfg.seed)
    train_df = load_split(cfg.paths.raw_dir, "KDDTrain+")
    test_sets = {}
    for split in cfg.evaluation.test_sets:
        test_sets[split] = mark_novel_attacks(load_split(cfg.paths.raw_dir, split), train_df)

    results = {}
    for profile in profiles or cfg.data.feature_profiles:
        model, selection = train_hybrid(cfg, nsl_kdd_spec(profile), train_df, run=profile)
        results[profile] = evaluate_model(cfg, model, profile, selection, test_sets)
    path = write_report(cfg, results, "RESULTS.md", "NetSentinel results - NSL-KDD")
    logger.info("done, report: %s", path)
    return results
