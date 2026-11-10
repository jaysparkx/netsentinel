"""
تجميع التنبيهات إلى "حوادث" (Incidents) — كما تفعل أنظمة SOC الحقيقية.

مسح منافذ واحد = 600 اتصال = 600 تنبيه متطابق. هذا يُغرق المحلّل الأمني
("إرهاق التنبيهات" Alert Fatigue). الحل: نجمع التنبيهات التي لها نفس
(المصدر، الهدف، نوع الهجوم) في حادثة واحدة مع عدد الاتصالات وأعلى درجة.
"""

from __future__ import annotations

import pandas as pd

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "none": 3}
INCIDENT_KEYS = ["src_ip", "dst_ip", "final_label"]


def group_incidents(features: pd.DataFrame, predictions: pd.DataFrame) -> pd.DataFrame:
    """
    يُرجع جدول حوادث مرتّباً بالخطورة ثم بعدد الاتصالات. لكل حادثة:
        representative : رقم السطر الأكثر شذوذاً (لعرض الشرح عليه)
        connections    : عدد الاتصالات في الحادثة
        dst_ports      : عدد المنافذ المختلفة المستهدفة (مؤشّر قوي على المسح)
    بيانات بلا عناوين IP (مثل CSV من NSL-KDD) ← كل تنبيه حادثة مستقلّة.
    """
    alerts = predictions[predictions["is_alert"] == 1]
    if alerts.empty:
        return pd.DataFrame()

    frame = alerts.join(features.drop(columns=alerts.columns, errors="ignore"))
    if not set(INCIDENT_KEYS) <= set(frame.columns):
        frame = frame.assign(src_ip="-", dst_ip="-", _row=range(len(frame)))
        keys = INCIDENT_KEYS + ["_row"]
    else:
        keys = INCIDENT_KEYS

    aggregations = {
        "severity": ("severity", "first"),
        "connections": ("final_label", "size"),
        "max_anomaly": ("anomaly_score", "max"),
        "mean_confidence": ("confidence", "mean"),
    }
    if "dst_port" in frame.columns:
        aggregations["dst_ports"] = ("dst_port", "nunique")

    grouped = frame.groupby(keys, sort=False)
    incidents = grouped.agg(**aggregations).reset_index()
    incidents["representative"] = grouped["anomaly_score"].idxmax().to_numpy()

    incidents["_order"] = incidents["severity"].map(SEVERITY_ORDER)
    return (incidents.sort_values(["_order", "connections"], ascending=[True, False])
            .drop(columns=["_order", "_row"], errors="ignore")
            .reset_index(drop=True))
