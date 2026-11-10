"""
توليد تقرير النتائج تلقائياً (Markdown بالعربية) من ملفات metrics.json.

الفائدة: كل مرة تعيد التدريب، يُعاد توليد التقرير بالأرقام الجديدة —
لا نسخ يدوي للأرقام، ولا أخطاء نقل.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from netsentinel.config import Config

RUN_TITLES_AR = {
    "full": "NSL-KDD — ملف الميزات الكامل (40 ميزة)",
    "live": "NSL-KDD — ملف الميزات الحي (28 ميزة من الترويسات فقط)",
    "cicids2017_random": "CIC-IDS2017 — تقسيم عشوائي (الطريقة الشائعة في الأبحاث)",
    "cicids2017_temporal": "CIC-IDS2017 — تقسيم زمني: تدريب الاثنين–الأربعاء، اختبار الخميس–الجمعة (Zero-day حقيقي)",
}


def _pct(x: float) -> str:
    return f"{x * 100:.2f}%"


def _table(df: pd.DataFrame) -> str:
    return df.to_markdown()


def _profile_section(res: dict) -> list[str]:
    meta = res["metadata"]
    lines = [
        f"## {RUN_TITLES_AR.get(res['profile'], res['profile'])}",
        "",
        f"- المصنِّف المختار: **{meta['classifier']}**",
        f"- كاشف الشذوذ المختار: **{meta['detector']}** (عتبة عند النسبة المئوية {meta['threshold_percentile']})",
        f"- سجلات التدريب: {meta['n_train']:,} — سجلات التحقق: {meta['n_validation']:,}"
        f" — أبعاد بعد الترميز: {meta['n_encoded_features']}",
        f"- الفئات التي رآها المصنِّف في التدريب: {', '.join(meta.get('train_classes', []))}",
        "",
        "### مقارنة المصنِّفات (مجموعة التحقق)",
        "",
        _table(pd.DataFrame(res["validation"]["classifier_comparison"]).T),
        "",
        "### مقارنة كواشف الشذوذ (مجموعة التحقق)",
        "",
        _table(pd.DataFrame(res["validation"]["detector_comparison"]).T),
        "",
    ]
    for split, m in res["test"].items():
        rows = {
            mode: {
                "Detection Rate": _pct(m[mode]["detection_rate"]),
                "False Alarm Rate": _pct(m[mode]["false_alarm_rate"]),
                "Precision": _pct(m[mode]["precision"]),
                "F1": f"{m[mode]['f1']:.4f}",
                "Accuracy": _pct(m[mode]["accuracy"]),
            }
            for mode in ("classifier_only", "anomaly_only", "hybrid")
        }
        lines += [
            f"### النتائج على {split} ({m['n_samples']:,} سجل — لم يرها النظام أثناء التدريب)",
            "",
            _table(pd.DataFrame(rows).T),
            "",
            f"- Macro-F1 للتصنيف متعدّد الفئات: **{m['multiclass']['f1_macro']:.4f}**",
            "",
            "نسبة الكشف لكل فئة (المصنِّف وحده ← الهجين):",
            "",
        ]
        by_cat = m["detection_rate_by_category"]
        for cat, val in by_cat["classifier_only"].items():
            if cat == "normal":
                continue
            lines.append(f"- {cat}: {_pct(val)} ← **{_pct(by_cat['hybrid'][cat])}**")
        if "novel_attacks" in m:
            n = m["novel_attacks"]
            lines += [
                "",
                f"**الهجمات الجديدة (غير موجودة في التدريب) — {n['n_samples']:,} سجل:**",
                "",
                f"| الوضع | نسبة الكشف |\n|---|---|\n"
                f"| المصنِّف وحده | {_pct(n['classifier_only_dr'])} |\n"
                f"| كاشف الشذوذ وحده | {_pct(n['anomaly_only_dr'])} |\n"
                f"| **الهجين** | **{_pct(n['hybrid_dr'])}** |",
                "",
                f"أنواعها: {', '.join(n['attack_types'])}",
            ]
        if m.get("threshold_sensitivity"):
            sens = pd.DataFrame(m["threshold_sensitivity"]).set_index("percentile")
            lines += ["", "**حساسية العتبة (النظام الهجين) — العتبات من طبيعي التحقق:**", "",
                      _table(sens[["detection_rate", "false_alarm_rate", "precision", "f1", "novel_dr"]]), ""]
        tag = split.replace("+", "plus")
        lines += [
            "",
            f"![confusion](./{res['profile']}/figures/confusion_{tag}.png)",
            f"![roc](./{res['profile']}/figures/roc_{tag}.png)",
            "",
        ]

    top = list(res["feature_importance"].items())[:10]
    lines += ["### أهم 10 ميزات (Permutation Importance)", ""]
    lines += [f"{i}. `{f}` — {v:.4f}" for i, (f, v) in enumerate(top, 1)]
    lines += ["", f"![importance](./{res['profile']}/figures/feature_importance.png)", ""]
    return lines


def write_report(cfg: Config, results: dict[str, dict], filename: str, title: str) -> Path:
    lines = [
        f"# {title}",
        "",
        "> هذا الملف مولَّد تلقائياً بواسطة `netsentinel train` — لا تعدّله يدوياً.",
        "",
    ]
    for res in results.values():
        lines += _profile_section(res)
    path = cfg.paths.reports_dir / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
