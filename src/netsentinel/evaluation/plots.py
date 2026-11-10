"""
الرسوم البيانية للتقرير البحثي.

ملاحظة: نكتب عناوين الرسوم بالإنجليزية لأن matplotlib لا يدعم تشكيل الحروف
العربية افتراضياً (تظهر مقطّعة ومعكوسة). الشرح العربي موجود في التقرير والتوثيق.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # رسم بدون نافذة (يعمل على السيرفر وفي الخلفية)

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve

from netsentinel.data.schema import CLASS_NAMES

sns.set_theme(style="whitegrid", context="notebook")


def _save(fig: plt.Figure, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_confusion_matrix(y_true, y_pred, path: Path, title: str, class_names: list[str] = CLASS_NAMES) -> Path:
    """مصفوفة الالتباس مطبَّعة بالصفوف: كل صف = الفئة الحقيقية، النسب = أين ذهبت."""
    labels = [c for c in class_names if c in set(y_true) | set(y_pred)]
    cm = confusion_matrix(y_true, y_pred, labels=labels, normalize="true")
    size = 5 + 0.5 * len(labels)
    fig, ax = plt.subplots(figsize=(size + 1, size))
    sns.heatmap(cm, annot=True, fmt=".2f", cmap="Blues", xticklabels=labels, yticklabels=labels, ax=ax)
    ax.set(xlabel="Predicted", ylabel="True", title=title)
    return _save(fig, path)


def plot_roc_curves(y_true, scores: dict[str, np.ndarray], path: Path, title: str) -> Path:
    """منحنى ROC لعدّة نماذج على نفس الرسم للمقارنة."""
    fig, ax = plt.subplots(figsize=(7, 6))
    for name, score in scores.items():
        fpr, tpr, _ = roc_curve(y_true, score)
        ax.plot(fpr, tpr, label=name, linewidth=2)
    ax.plot([0, 1], [0, 1], "k--", alpha=0.4, label="random")
    ax.set(xlabel="False Alarm Rate", ylabel="Detection Rate", title=title)
    ax.legend(loc="lower right")
    return _save(fig, path)


def plot_anomaly_scores(scores: np.ndarray, is_attack: np.ndarray, threshold: float, path: Path) -> Path:
    """توزيع درجات الشذوذ للطبيعي مقابل الهجمات، مع خطّ العتبة."""
    fig, ax = plt.subplots(figsize=(8, 5))
    clip = np.percentile(scores, 99.5)
    for label, mask, color in [("normal", is_attack == 0, "tab:green"), ("attack", is_attack == 1, "tab:red")]:
        ax.hist(np.clip(scores[mask], None, clip), bins=80, alpha=0.55, label=label, color=color, density=True)
    ax.axvline(threshold, color="black", linestyle="--", label=f"threshold = {threshold:.4f}")
    ax.set(xlabel="Anomaly score", ylabel="Density", title="Anomaly score distribution")
    ax.legend()
    return _save(fig, path)


def plot_model_comparison(table: pd.DataFrame, path: Path) -> Path:
    """مقارنة المصنِّفات على مجموعة التحقق."""
    melted = table.reset_index(names="model").melt(id_vars="model", var_name="metric", value_name="score")
    fig, ax = plt.subplots(figsize=(9, 5))
    sns.barplot(data=melted, x="model", y="score", hue="metric", ax=ax)
    ax.set(ylim=(0, 1.05), title="Supervised model comparison (validation set)", xlabel="")
    ax.tick_params(axis="x", rotation=15)
    return _save(fig, path)


def plot_feature_importance(importance: pd.Series, path: Path, top_n: int = 20) -> Path:
    """أهم الميزات حسب Permutation Importance."""
    top = importance.sort_values(ascending=True).tail(top_n)
    fig, ax = plt.subplots(figsize=(8, 7))
    ax.barh(top.index, top.values, color="tab:blue")
    ax.set(xlabel="Drop in macro-F1 when feature is shuffled", title=f"Top {top_n} features")
    return _save(fig, path)


def plot_novel_detection(novel: dict, path: Path) -> Path:
    """الرسم الأهم بحثياً: نسبة كشف الهجمات الجديدة لكل وضع."""
    modes = ["classifier_only_dr", "anomaly_only_dr", "hybrid_dr"]
    names = ["Classifier only", "Anomaly only", "Hybrid"]
    values = [novel[m] for m in modes]
    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(names, values, color=["tab:blue", "tab:orange", "tab:green"])
    ax.bar_label(bars, labels=[f"{v:.1%}" for v in values])
    ax.set(ylim=(0, 1.05), ylabel="Detection rate", title=f"Novel (unseen) attacks — n={novel['n_samples']}")
    return _save(fig, path)


def plot_threshold_sensitivity(rows: list[dict], path: Path) -> Path:
    """منحنى التشغيل: الكشف مقابل الإنذار الكاذب للنظام الهجين عند كل عتبة."""
    fig, ax = plt.subplots(figsize=(7, 5))
    far = [r["false_alarm_rate"] for r in rows]
    dr = [r["detection_rate"] for r in rows]
    ax.plot(far, dr, "o-", linewidth=2)
    for r in rows:
        ax.annotate(f"p{r['percentile']:g}", (r["false_alarm_rate"], r["detection_rate"]),
                    textcoords="offset points", xytext=(6, -12), fontsize=9)
    ax.set(xlabel="False Alarm Rate", ylabel="Detection Rate", title="Hybrid operating points (threshold percentile)")
    return _save(fig, path)
