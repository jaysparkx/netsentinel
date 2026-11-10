"""
أهمية الميزات عبر Permutation Importance.

الطريقة (سهلة الشرح للفريق وللّجنة):
    1. نقيس أداء النموذج (Macro-F1) على بيانات لم يتدرّب عليها.
    2. نأخذ عموداً واحداً (مثلاً src_bytes) ونخلط قيمه عشوائياً بين السطور
       → العلاقة بين هذا العمود والتسمية تنكسر.
    3. نقيس الأداء من جديد. مقدار الانخفاض = أهمية هذا العمود.
    4. نكرّر لكل عمود.

ميزتها على "feature_importances_" الخاصة بالأشجار: تعمل مع أي نموذج،
وتقيس الأهمية على الميزات الأصلية (service) لا على أعمدة One-Hot المفكّكة.
"""

from __future__ import annotations

import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.pipeline import Pipeline

from netsentinel.features.preprocessing import select_features
from netsentinel.models.hybrid import HybridIDS


def compute_permutation_importance(
    model: HybridIDS, df: pd.DataFrame, n_samples: int = 3000, seed: int = 42,
) -> pd.Series:
    """يُرجع Series: اسم الميزة → متوسط الانخفاض في Macro-F1 (مرتّبة تنازلياً)."""
    sample = df.sample(n=min(n_samples, len(df)), random_state=seed)
    # نلفّ المعالجة + المصنِّف المدرَّبَين في Pipeline واحد حتى نخلط الأعمدة الأصلية
    estimator = Pipeline([("prep", model.preprocessor), ("clf", model.classifier)])
    result = permutation_importance(
        estimator,
        select_features(sample, model.spec),
        sample["category"],
        scoring="f1_macro",
        n_repeats=5,
        random_state=seed,
        n_jobs=-1,
    )
    return pd.Series(result.importances_mean, index=model.features).sort_values(ascending=False)
