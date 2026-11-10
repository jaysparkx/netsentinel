"""
خطّ المعالجة المسبقة (Preprocessing Pipeline).

النماذج الرياضية لا تفهم نصوصاً مثل "tcp" أو "http"، ولا تتعامل جيداً مع
أرقام بمقاييس مختلفة جداً (src_bytes قد تصل لمليار، بينما serror_rate بين 0 و1).
لذلك نمرّر كل عمود بالتحويل المناسب له:

    ┌───────────────────────┬─────────────────────────────────────────────┐
    │ نوع العمود            │ التحويل                                      │
    ├───────────────────────┼─────────────────────────────────────────────┤
    │ نصّي (فئوي)           │ One-Hot: "tcp" → [1,0,0] , "udp" → [0,1,0]  │
    │ رقمي بذيل طويل        │ signed log1p ثم Standardize                 │
    │ رقمي عادي             │ Standardize: (x - المتوسط) / الانحراف       │
    └───────────────────────┴─────────────────────────────────────────────┘

مهمّ جداً: الـ pipeline يتعلّم (fit) المتوسطات والفئات من بيانات التدريب فقط،
ثم يطبّقها (transform) كما هي على الاختبار → لا تسرّب للبيانات (No data leakage).

كل الدوال هنا تأخذ DatasetSpec، فتعمل على NSL-KDD و CIC-IDS2017 بنفس الكود.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from netsentinel.data.spec import DatasetSpec


def signed_log1p(x):
    """
    sign(x) · log(1 + |x|)  — مثل log1p للقيم الموجبة، لكنه يقبل السالبة أيضاً.
    (بعض ميزات CICFlowMeter سالبة مثل Init_Win_bytes = −1، و log1p(−1) = −∞.)
    """
    return np.sign(x) * np.log1p(np.abs(x))


def build_preprocessor(spec: DatasetSpec) -> ColumnTransformer:
    """
    يبني ColumnTransformer حسب مواصفات البيانات.

    handle_unknown="ignore": إذا ظهرت قيمة نصية جديدة في الاختبار لم تُرَ في التدريب
    (مثلاً service جديدة)، تُرمَّز كأصفار بدل أن يتعطّل البرنامج.
    """
    regular = [f for f in spec.features if f not in spec.categorical and f not in spec.skewed]
    log_then_scale = Pipeline([
        ("log", FunctionTransformer(signed_log1p, feature_names_out="one-to-one")),
        ("scale", StandardScaler()),
    ])
    transformers = [
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), spec.categorical),
        ("skewed", log_then_scale, spec.skewed),
        ("num", StandardScaler(), regular),
    ]
    return ColumnTransformer(
        transformers=[t for t in transformers if t[2]],   # نتجاهل الفروع الفارغة
        remainder="drop",
        verbose_feature_names_out=True,
    )


def select_features(df: pd.DataFrame, spec: DatasetSpec) -> pd.DataFrame:
    """يُرجع فقط أعمدة الميزات الخاصة بالمواصفات، بالترتيب الصحيح."""
    missing = [c for c in spec.features if c not in df.columns]
    if missing:
        raise ValueError(f"Missing feature columns for '{spec.name}/{spec.profile}': {missing}")
    return df[spec.features]
