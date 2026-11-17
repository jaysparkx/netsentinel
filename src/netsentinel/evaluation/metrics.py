import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)

from netsentinel.data.schema import CLASS_NAMES

# detection rate = recall on attacks, false alarm rate = FP / (FP + TN)


def binary_metrics(y_true, y_pred, y_score=None):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    m = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "detection_rate": recall_score(y_true, y_pred, zero_division=0),
        "false_alarm_rate": fp / (fp + tn) if (fp + tn) else 0.0,
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }
    if y_score is not None and len(np.unique(y_true)) == 2:
        m["roc_auc"] = roc_auc_score(y_true, y_score)
    return {k: (round(float(v), 4) if isinstance(v, float) else v) for k, v in m.items()}


def multiclass_metrics(y_true, y_pred, class_names=CLASS_NAMES):
    labels = [c for c in class_names if c in set(y_true) | set(y_pred)]
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "f1_macro": round(float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)), 4),
        "per_class": classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0),
    }


def detection_rate_by_group(is_alert, groups):
    frame = pd.DataFrame({"alert": is_alert, "group": groups.to_numpy()})
    return {str(k): round(float(v), 4) for k, v in frame.groupby("group")["alert"].mean().items()}


def attack_score(predictions):
    # rough "attack probability" from the classifier, used for the ROC curve
    conf = predictions["confidence"].to_numpy()
    is_normal = predictions["classifier_label"].to_numpy() == "normal"
    return np.where(is_normal, 1 - conf, conf)


def evaluate_hybrid(test_df, predictions, class_names=CLASS_NAMES):
    """Compare classifier only, anomaly detector only and the hybrid on one test set."""
    y_true = test_df["is_attack"].to_numpy()
    clf_alert = (predictions["classifier_label"] != "normal").astype(int).to_numpy()
    anom_alert = predictions["is_anomaly"].to_numpy()
    hybrid_alert = predictions["is_alert"].to_numpy()

    result = {
        "n_samples": int(len(test_df)),
        "classifier_only": binary_metrics(y_true, clf_alert, attack_score(predictions)),
        "anomaly_only": binary_metrics(y_true, anom_alert, predictions["anomaly_score"].to_numpy()),
        "hybrid": binary_metrics(y_true, hybrid_alert),
        "multiclass": multiclass_metrics(test_df["category"], predictions["classifier_label"].to_numpy(), class_names),
        "detection_rate_by_category": {
            "classifier_only": detection_rate_by_group(clf_alert, test_df["category"]),
            "hybrid": detection_rate_by_group(hybrid_alert, test_df["category"]),
        },
    }

    # attacks never seen in training
    if "is_novel" in test_df.columns and test_df["is_novel"].any():
        novel = test_df["is_novel"].to_numpy() == 1
        result["novel_attacks"] = {
            "n_samples": int(novel.sum()),
            "attack_types": sorted(test_df.loc[novel, "attack"].unique().tolist()),
            "classifier_only_dr": round(float(clf_alert[novel].mean()), 4),
            "anomaly_only_dr": round(float(anom_alert[novel].mean()), 4),
            "hybrid_dr": round(float(hybrid_alert[novel].mean()), 4),
        }
    return result
