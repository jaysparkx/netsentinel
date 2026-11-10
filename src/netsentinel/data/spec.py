"""
"مواصفات مجموعة البيانات" (DatasetSpec) — ما يحتاجه النظام ليعمل على أي مجموعة بيانات.

بدل أن يكون الكود مربوطاً بـ NSL-KDD، كل جزء (المعالجة، النظام الهجين، التفسير)
يقرأ من هذا الكائن: ما الميزات؟ أيها نصّي؟ أيها يحتاج log؟ ما وصفها بالعربية؟
النتيجة: نفس الكود يعمل على NSL-KDD (1998) و CIC-IDS2017 (حركة حقيقية حديثة).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DatasetSpec:
    name: str                        # اسم مجموعة البيانات (للتقارير)
    profile: str                     # اسم ملف الميزات / التجربة
    features: list[str]              # أعمدة الإدخال بالترتيب
    categorical: list[str]           # أعمدة نصية ← One-Hot
    skewed: list[str]                # أعمدة بذيل طويل ← signed log1p
    class_names: list[str]           # ترتيب الفئات في الرسوم والتقارير
    descriptions: dict[str, str] = field(default_factory=dict)   # وصف عربي لكل ميزة

    def describe(self, feature: str) -> str:
        return self.descriptions.get(feature, feature)


def nsl_kdd_spec(profile: str) -> DatasetSpec:
    """مواصفات NSL-KDD لملف الميزات full أو live."""
    from netsentinel.data import schema

    features = schema.FEATURE_PROFILES[profile]
    return DatasetSpec(
        name="NSL-KDD",
        profile=profile,
        features=features,
        categorical=[f for f in features if f in schema.CATEGORICAL_FEATURES],
        skewed=[f for f in features if f in schema.SKEWED_FEATURES],
        class_names=schema.CLASS_NAMES,
        descriptions=schema.FEATURE_DESCRIPTIONS_AR,
    )
