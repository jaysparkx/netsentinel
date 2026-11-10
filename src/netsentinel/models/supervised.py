"""
المصنِّفات المُشرَفة (Supervised Classifiers).

"مُشرَف" = نعطي النموذج أمثلة مع الإجابة الصحيحة (هذا اتصال DoS، هذا طبيعي...)
فيتعلّم القواعد التي تفرّق بينها.

نقارن أربع عائلات مختلفة من الخوارزميات حتى يكون الاختيار مبنيّاً على دليل:

    1. Random Forest          — مئات أشجار القرار، كل شجرة ترى جزءاً عشوائياً من
                                 البيانات، والقرار بالتصويت. قويّ ومقاوم للضوضاء.
    2. Hist Gradient Boosting — أشجار تُبنى بالتتابع، كل شجرة تصحّح أخطاء السابقة.
                                 غالباً الأدقّ على البيانات الجدولية.
    3. Logistic Regression    — نموذج خطّي بسيط، خطّ أساس (Baseline) للمقارنة.
    4. MLP (شبكة عصبية)       — طبقات من الخلايا العصبية تتعلّم علاقات غير خطية.

مشكلة عدم التوازن (Class Imbalance):
    في بيانات التدريب: ~67 ألف طبيعي مقابل 52 فقط من U2R!
    لو لم نعالج ذلك، سيتجاهل النموذج U2R تماماً ويبقى "دقيقاً" ظاهرياً.
    الحل: class_weight="balanced" → خطأ واحد في U2R يُحسب كأخطاء كثيرة في normal.
"""

from __future__ import annotations

from typing import Callable

from sklearn.base import ClassifierMixin
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier


def _random_forest(seed: int) -> ClassifierMixin:
    return RandomForestClassifier(
        n_estimators=300,
        min_samples_leaf=1,
        class_weight="balanced_subsample",   # يوازن الفئات داخل كل شجرة
        n_jobs=-1,
        random_state=seed,
    )


def _hist_gradient_boosting(seed: int) -> ClassifierMixin:
    return HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.1,
        class_weight="balanced",
        early_stopping=True,                 # يتوقف عندما يتوقف التحسّن → يمنع الإفراط في التعلّم
        random_state=seed,
    )


def _logistic_regression(seed: int) -> ClassifierMixin:
    return LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed)


def _mlp(seed: int) -> ClassifierMixin:
    # ملاحظة: MLPClassifier لا يدعم class_weight، فهو مقياس مفيد لأثر عدم التوازن.
    return MLPClassifier(
        hidden_layer_sizes=(128, 64),
        early_stopping=True,
        max_iter=200,
        random_state=seed,
    )


SUPERVISED_MODELS: dict[str, Callable[[int], ClassifierMixin]] = {
    "random_forest": _random_forest,
    "hist_gradient_boosting": _hist_gradient_boosting,
    "logistic_regression": _logistic_regression,
    "mlp": _mlp,
}


def build_classifier(name: str, seed: int = 42) -> ClassifierMixin:
    """مصنع (Factory): يُنشئ مصنِّفاً جديداً غير مدرَّب بالاسم."""
    if name not in SUPERVISED_MODELS:
        raise ValueError(f"Unknown classifier '{name}'. Options: {list(SUPERVISED_MODELS)}")
    return SUPERVISED_MODELS[name](seed)
