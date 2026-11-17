import matplotlib

matplotlib.use("Agg")  # no window, just save png files

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve

from netsentinel.data.schema import CLASS_NAMES

sns.set_theme(style="whitegrid")


def _save(fig, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_confusion_matrix(y_true, y_pred, path, title, class_names=CLASS_NAMES):
    labels = [c for c in class_names if c in set(y_true) | set(y_pred)]
    cm = confusion_matrix(y_true, y_pred, labels=labels, normalize="true")
    size = 5 + 0.5 * len(labels)
    fig, ax = plt.subplots(figsize=(size + 1, size))
    sns.heatmap(cm, annot=True, fmt=".2f", cmap="Blues", xticklabels=labels, yticklabels=labels, ax=ax)
    ax.set(xlabel="Predicted", ylabel="True", title=title)
    _save(fig, path)


def plot_roc_curves(y_true, scores, path, title):
    fig, ax = plt.subplots(figsize=(7, 6))
    for name, score in scores.items():
        fpr, tpr, _ = roc_curve(y_true, score)
        ax.plot(fpr, tpr, label=name, linewidth=2)
    ax.plot([0, 1], [0, 1], "k--", alpha=0.4, label="random")
    ax.set(xlabel="False Alarm Rate", ylabel="Detection Rate", title=title)
    ax.legend(loc="lower right")
    _save(fig, path)


def plot_anomaly_scores(scores, is_attack, threshold, path):
    fig, ax = plt.subplots(figsize=(8, 5))
    clip = np.percentile(scores, 99.5)
    ax.hist(np.clip(scores[is_attack == 0], None, clip), bins=80, alpha=0.55, label="normal", color="tab:green", density=True)
    ax.hist(np.clip(scores[is_attack == 1], None, clip), bins=80, alpha=0.55, label="attack", color="tab:red", density=True)
    ax.axvline(threshold, color="black", linestyle="--", label=f"threshold = {threshold:.4f}")
    ax.set(xlabel="Anomaly score", ylabel="Density", title="Anomaly score distribution")
    ax.legend()
    _save(fig, path)


def plot_model_comparison(table, path):
    melted = table.reset_index(names="model").melt(id_vars="model", var_name="metric", value_name="score")
    fig, ax = plt.subplots(figsize=(9, 5))
    sns.barplot(data=melted, x="model", y="score", hue="metric", ax=ax)
    ax.set(ylim=(0, 1.05), title="Model comparison (validation set)", xlabel="")
    ax.tick_params(axis="x", rotation=15)
    _save(fig, path)


def plot_feature_importance(importance, path, top_n=20):
    top = importance.sort_values(ascending=True).tail(top_n)
    fig, ax = plt.subplots(figsize=(8, 7))
    ax.barh(top.index, top.values, color="tab:blue")
    ax.set(xlabel="Drop in macro-F1 when shuffled", title=f"Top {top_n} features")
    _save(fig, path)


def plot_novel_detection(novel, path):
    names = ["Classifier only", "Anomaly only", "Hybrid"]
    values = [novel["classifier_only_dr"], novel["anomaly_only_dr"], novel["hybrid_dr"]]
    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(names, values, color=["tab:blue", "tab:orange", "tab:green"])
    ax.bar_label(bars, labels=[f"{v:.1%}" for v in values])
    ax.set(ylim=(0, 1.05), ylabel="Detection rate", title=f"Attacks not seen in training (n={novel['n_samples']})")
    _save(fig, path)


def plot_threshold_sensitivity(rows, path):
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot([r["false_alarm_rate"] for r in rows], [r["detection_rate"] for r in rows], "o-", linewidth=2)
    for r in rows:
        ax.annotate(f"p{r['percentile']:g}", (r["false_alarm_rate"], r["detection_rate"]),
                    textcoords="offset points", xytext=(6, -12), fontsize=9)
    ax.set(xlabel="False Alarm Rate", ylabel="Detection Rate", title="Hybrid at different thresholds")
    _save(fig, path)
