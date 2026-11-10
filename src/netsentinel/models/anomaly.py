"""
كواشف الشذوذ غير المُشرَفة (Unsupervised Anomaly Detectors).

الفكرة: لا نُعلّم النموذج شكل الهجمات — نُعلّمه شكل "الطبيعي" فقط.
أي اتصال يختلف كثيراً عن الطبيعي يحصل على "درجة شذوذ" عالية.

لماذا هذا مهم أمنياً؟
    المصنِّف المُشرَف لا يعرف إلا الهجمات التي رآها في التدريب.
    المهاجم الذي يستخدم أسلوباً جديداً (Zero-day) قد يمرّ منه.
    أما كاشف الشذوذ فلا يهمّه اسم الهجوم، بل فقط: "هل هذا يشبه الطبيعي؟"

كل كاشف هنا يوفّر نفس الواجهة:
    fit(X_normal)     → يتعلّم من الحركة الطبيعية فقط
    score(X)          → درجة شذوذ لكل سجل (أعلى = أغرب)
    calibrate(X, p)   → يحدّد العتبة: أي درجة فوقها = شاذّ
    predict(X)        → 0 طبيعي / 1 شاذّ
"""

from __future__ import annotations

import warnings
from abc import ABC, abstractmethod

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPRegressor


class AnomalyDetector(ABC):
    """الصنف الأساسي المجرّد: يحدّد الواجهة المشتركة ومنطق العتبة."""

    def __init__(self) -> None:
        self.threshold_: float | None = None

    @abstractmethod
    def fit(self, X_normal: np.ndarray) -> "AnomalyDetector":
        ...

    @abstractmethod
    def score(self, X: np.ndarray) -> np.ndarray:
        """درجة الشذوذ: كلما زادت، كان السجل أبعد عن الطبيعي."""

    def calibrate(self, X_normal: np.ndarray, percentile: float = 99.0) -> float:
        """
        يحسب العتبة من بيانات طبيعية لم يتدرّب عليها النموذج (بيانات تحقق).

        percentile=99 يعني: نختار العتبة بحيث 99% من الحركة الطبيعية تقع تحتها
        → نسبة الإنذارات الكاذبة المتوقّعة من هذه الطبقة ≈ 1%.
        هذا هو "المقبض" الذي يوازن بين كشف أكثر وإزعاج أقل.
        """
        self.threshold_ = float(np.percentile(self.score(X_normal), percentile))
        return self.threshold_

    def predict(self, X: np.ndarray) -> np.ndarray:
        if self.threshold_ is None:
            raise RuntimeError("Detector is not calibrated — call calibrate() first.")
        return (self.score(X) > self.threshold_).astype(int)


class IsolationForestDetector(AnomalyDetector):
    """
    Isolation Forest — "غابة العزل".

    الحدس: النقطة الشاذّة سهلة العزل. لو قسّمنا البيانات عشوائياً مراراً،
    النقطة الغريبة تنعزل وحدها بعد تقسيمات قليلة، بينما النقطة الطبيعية
    (المحاطة بنقاط كثيرة تشبهها) تحتاج تقسيمات أكثر.
    → متوسط "عمق العزل" القصير = شذوذ عالٍ.
    """

    def __init__(self, n_estimators: int = 300, seed: int = 42) -> None:
        super().__init__()
        self.model = IsolationForest(
            n_estimators=n_estimators, contamination="auto", n_jobs=-1, random_state=seed,
        )

    def fit(self, X_normal: np.ndarray) -> "IsolationForestDetector":
        self.model.fit(X_normal)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        # score_samples يعطي قيمة أعلى للطبيعي، لذلك نعكس الإشارة
        return -self.model.score_samples(X)


class AutoencoderDetector(AnomalyDetector):
    """
    Autoencoder — "المُرمِّز الذاتي" (شبكة عصبية).

    الحدس: نضغط السجل (≈120 رقماً) في عنق زجاجة صغير (8 أرقام) ثم نحاول
    إعادة بنائه. الشبكة تتدرّب على الطبيعي فقط، فتتقن إعادة بناء الطبيعي.
    عندما يمرّ اتصال هجومي، تفشل في إعادة بنائه بدقة
    → خطأ إعادة البناء (Reconstruction Error) الكبير = شذوذ.

        الإدخال (120) → 64 → 16 → [8] → 16 → 64 → الإخراج (120)
                       ───── ترميز ─────   ──── فكّ ترميز ────
    """

    def __init__(self, hidden_layers: tuple[int, ...] = (64, 16, 8, 16, 64), epochs: int = 60, seed: int = 42) -> None:
        super().__init__()
        # ملاحظة تجريبية: مع early_stopping توقّف التدريب بعد ~13 دورة فقط وبقيت
        # الشبكة "غير ناضجة" (نسبة كشف ~2%). عدد دورات ثابت (60) رفعها إلى ~89%
        # على التحقق. لذلك نثبّت عدد الدورات بدل الإيقاف المبكر.
        self.model = MLPRegressor(
            hidden_layer_sizes=hidden_layers,
            activation="relu",
            early_stopping=False,
            max_iter=epochs,
            random_state=seed,
        )

    def fit(self, X_normal: np.ndarray) -> "AutoencoderDetector":
        # الهدف = الإدخال نفسه: الشبكة تتعلّم أن "تنسخ" الطبيعي عبر عنق الزجاجة
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)   # متوقَّع: عدد دورات ثابت عمداً
            self.model.fit(X_normal, X_normal)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        reconstruction = self.model.predict(X)
        return np.mean((X - reconstruction) ** 2, axis=1)   # MSE لكل سجل


ANOMALY_MODELS = {
    "isolation_forest": IsolationForestDetector,
    "autoencoder": AutoencoderDetector,
}


def build_detector(name: str, seed: int = 42) -> AnomalyDetector:
    if name not in ANOMALY_MODELS:
        raise ValueError(f"Unknown detector '{name}'. Options: {list(ANOMALY_MODELS)}")
    return ANOMALY_MODELS[name](seed=seed)
