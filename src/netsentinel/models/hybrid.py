"""
النظام الهجين (Hybrid IDS) — قلب المشروع.

يجمع طبقتين بقاعدة دمج قرار (Decision Fusion) بسيطة وقابلة للتفسير:

                         ┌──────────────────────────┐
     اتصال شبكي ──►  المعالجة المسبقة  ──►│ 1) المصنِّف المُشرَف      │──► فئة: DoS / Probe / R2L / U2R / normal
                         │ 2) كاشف الشذوذ            │──► درجة شذوذ + (شاذّ؟)
                         └──────────────────────────┘
                                      │
                                      ▼
            ┌───────────────────────────────────────────────────────┐
            │ إذا قال المصنِّف "هجوم"           → نعتمد نوع الهجوم   │
            │ إذا قال "طبيعي" لكن الكاشف "شاذّ" → Unknown-Anomaly    │
            │ غير ذلك                           → normal              │
            └───────────────────────────────────────────────────────┘

الفائدة: المصنِّف يعطي دقة عالية وتسمية واضحة للهجمات المعروفة، وكاشف الشذوذ
يعمل كـ"شبكة أمان" تلتقط ما فات المصنِّف (الهجمات الجديدة).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.base import ClassifierMixin
from sklearn.compose import ColumnTransformer

from netsentinel.data.schema import NORMAL_LABEL
from netsentinel.data.spec import DatasetSpec
from netsentinel.features.preprocessing import select_features, signed_log1p
from netsentinel.models.anomaly import AnomalyDetector

UNKNOWN_ANOMALY = "Unknown-Anomaly"
MIN_BASELINE_STD = 0.05   # حدّ أدنى للانحراف المعياري عند حساب z (انظر explain)
MAX_Z = 99.0              # سقف لقيمة z المعروضة

# درجة الخطورة لكل فئة — تُستخدم لترتيب التنبيهات في لوحة التحكم
SEVERITY = {
    NORMAL_LABEL: "none",
    "Probe": "medium",
    UNKNOWN_ANOMALY: "medium",
    "DoS": "high",
    "R2L": "high",
    "U2R": "critical",
    # فئات CIC-IDS2017
    "PortScan": "medium",
    "DDoS": "high",
    "BruteForce": "high",
    "WebAttack": "high",
    "Bot": "critical",
    "Infiltration": "critical",
    "Heartbleed": "critical",
}


@dataclass
class NormalBaseline:
    """
    "بصمة" الحركة الطبيعية: متوسط وانحراف كل ميزة رقمية + تكرار القيم النصية.
    نستخدمها لشرح التنبيه: "لماذا اعتُبر هذا الاتصال مشبوهاً؟"
    """
    mean: pd.Series
    std: pd.Series
    category_freq: dict[str, pd.Series] = field(default_factory=dict)

    @classmethod
    def from_frame(cls, X_normal: pd.DataFrame, spec: DatasetSpec) -> "NormalBaseline":
        numeric = _numeric_view(X_normal, spec)
        freqs = {c: X_normal[c].value_counts(normalize=True) for c in spec.categorical}
        return cls(mean=numeric.mean(), std=numeric.std().replace(0, 1e-6), category_freq=freqs)


def _numeric_view(df: pd.DataFrame, spec: DatasetSpec) -> pd.DataFrame:
    """الأعمدة الرقمية بعد نفس تحويل log المستخدم في المعالجة، حتى تكون المقارنة عادلة."""
    numeric = df.drop(columns=spec.categorical).astype(float)
    numeric[spec.skewed] = signed_log1p(numeric[spec.skewed])
    return numeric


class HybridIDS:
    """النظام الكامل: معالجة + مصنِّف + كاشف شذوذ + بصمة الطبيعي."""

    def __init__(
        self,
        spec: DatasetSpec,
        preprocessor: ColumnTransformer,
        classifier: ClassifierMixin,
        detector: AnomalyDetector,
        baseline: NormalBaseline,
        metadata: dict | None = None,
    ) -> None:
        self.spec = spec
        self.preprocessor = preprocessor
        self.classifier = classifier
        self.detector = detector
        self.baseline = baseline
        self.metadata = metadata or {}

    @property
    def profile(self) -> str:
        return self.spec.profile

    @property
    def features(self) -> list[str]:
        return self.spec.features

    # ------------------------------------------------------------------ التنبّؤ
    def transform(self, df: pd.DataFrame) -> np.ndarray:
        return self.preprocessor.transform(select_features(df, self.spec))

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        يُرجع جدولاً بنفس عدد السطور، فيه لكل اتصال:
            classifier_label : رأي المصنِّف
            confidence       : ثقة المصنِّف (أعلى احتمال)
            anomaly_score    : درجة الشذوذ
            is_anomaly       : هل تجاوزت العتبة؟
            final_label      : القرار النهائي بعد الدمج
            is_alert         : هل نُطلق تنبيهاً؟
            severity         : الخطورة
        """
        X = self.transform(df)
        proba = self.classifier.predict_proba(X)
        classes = self.classifier.classes_
        clf_label = classes[proba.argmax(axis=1)]
        anomaly_score = self.detector.score(X)
        is_anomaly = anomaly_score > self.detector.threshold_

        final = np.where(
            clf_label != NORMAL_LABEL, clf_label,
            np.where(is_anomaly, UNKNOWN_ANOMALY, NORMAL_LABEL),
        )
        return pd.DataFrame({
            "classifier_label": clf_label,
            "confidence": proba.max(axis=1).round(4),
            "anomaly_score": anomaly_score.round(6),
            "is_anomaly": is_anomaly.astype(int),
            "final_label": final,
            "is_alert": (final != NORMAL_LABEL).astype(int),
            "severity": pd.Series(final).map(SEVERITY).to_numpy(),
        }, index=df.index)

    # ------------------------------------------------------------------ التفسير
    def explain(self, row: pd.Series, top_k: int = 5) -> list[dict]:
        """
        يشرح سجلاً واحداً: ما الميزات الأبعد عن الحركة الطبيعية؟

        نستخدم z-score:  z = (القيمة − متوسط الطبيعي) / انحراف الطبيعي
        |z| = 5 يعني أن القيمة تبعد 5 انحرافات معيارية عن المعتاد — شيء نادر جداً.
        للميزات النصية: إذا كانت القيمة نادرة في الحركة الطبيعية (<1%) نذكرها.
        """
        row_df = select_features(row.to_frame().T, self.spec)
        numeric = _numeric_view(row_df, self.spec).iloc[0]
        # حدّ أدنى للانحراف: ميزة لم تتغيّر أبداً في الطبيعي (std = 0) كانت ستعطي z بالملايين.
        # 0.05 بعد تحويل log ≈ تغيّر 5% — فوقه نقول "غير معتاد" دون مبالغة رقمية.
        std = self.baseline.std.clip(lower=MIN_BASELINE_STD)
        z = ((numeric - self.baseline.mean) / std).clip(-MAX_Z, MAX_Z).dropna()

        reasons = [
            {
                "feature": feat,
                "value": row[feat],
                "z_score": round(float(z[feat]), 2),
                "description": self.spec.describe(feat),
            }
            for feat in z.abs().sort_values(ascending=False).index[:top_k]
            if abs(z[feat]) >= 2
        ]
        for feat, freq in self.baseline.category_freq.items():
            share = float(freq.get(row[feat], 0.0))
            if share < 0.01:
                reasons.append({
                    "feature": feat,
                    "value": row[feat],
                    "z_score": None,
                    "description": f"{self.spec.describe(feat)} — قيمة نادرة في الحركة الطبيعية ({share:.2%})",
                })
        return reasons

    # ------------------------------------------------------- إعادة ضبط خط الأساس
    def refit_baseline(self, df_normal: pd.DataFrame, percentile: float = 99.0, seed: int = 42) -> None:
        """
        يعيد تدريب كاشف الشذوذ على حركة طبيعية من شبكتك أنت.

        لماذا؟ NSL-KDD سُجّلت عام 1998. شبكتك اليوم مختلفة (HTTPS، سحابة...).
        كاشف الشذوذ يحتاج أن يعرف "طبيعي شبكتك" لا "طبيعي 1998".
        """
        X = self.transform(df_normal)
        # خلط عشوائي قبل التقسيم: لو قسّمنا بالترتيب الزمني، ستقع اتصالات "بداية الالتقاط"
        # (النوافذ الإحصائية ما زالت فارغة) كلها في جزء التدريب، فتُعايَر العتبة على حركة
        # "مستقرّة" فقط وتُطلق إنذارات كاذبة في أول ثوانٍ من كل التقاط. (اكتُشف على حزم حقيقية.)
        order = np.random.default_rng(seed).permutation(len(X))
        split = int(len(X) * 0.8)
        self.detector.fit(X[order[:split]])
        self.detector.calibrate(X[order[split:]], percentile)
        self.baseline = NormalBaseline.from_frame(select_features(df_normal, self.spec), self.spec)
        self.metadata["baseline_source"] = "custom"

    # ------------------------------------------------------------- الحفظ/التحميل
    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path: Path) -> "HybridIDS":
        model = joblib.load(path)
        if not isinstance(model, HybridIDS):
            raise TypeError(f"{path} does not contain a HybridIDS model")
        return model
