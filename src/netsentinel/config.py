"""
تحميل الإعدادات من ملف YAML وتحويلها إلى كائنات Python واضحة الأنواع.

لماذا dataclasses بدل القواميس (dict)؟
    - الخطأ الإملائي في اسم إعداد يظهر فوراً بدل أن يمرّ بصمت.
    - المحرّر (IDE) يُكمل الأسماء تلقائياً، والكود يصبح أسهل للقراءة.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

# جذر المشروع = مجلدان فوق هذا الملف (src/netsentinel/config.py → المشروع)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "default.yaml"


@dataclass
class PathsConfig:
    raw_dir: Path = PROJECT_ROOT / "data" / "raw"
    artifacts_dir: Path = PROJECT_ROOT / "artifacts"
    reports_dir: Path = PROJECT_ROOT / "reports"


@dataclass
class DataConfig:
    validation_size: float = 0.2
    feature_profiles: list[str] = field(default_factory=lambda: ["full", "live"])


@dataclass
class SupervisedConfig:
    candidates: list[str] = field(
        default_factory=lambda: ["random_forest", "hist_gradient_boosting", "logistic_regression", "mlp"]
    )
    selection_metric: str = "f1_macro"


@dataclass
class AnomalyConfig:
    candidates: list[str] = field(default_factory=lambda: ["isolation_forest", "autoencoder"])
    threshold_percentile: float = 99.0


@dataclass
class EvaluationConfig:
    test_sets: list[str] = field(default_factory=lambda: ["KDDTest+", "KDDTest-21"])
    permutation_importance_samples: int = 3000


@dataclass
class CicidsConfig:
    normal_train_samples: int = 250_000
    attack_cap_per_type: int = 50_000
    random_test_size: float = 0.3


@dataclass
class Config:
    seed: int = 42
    paths: PathsConfig = field(default_factory=PathsConfig)
    data: DataConfig = field(default_factory=DataConfig)
    supervised: SupervisedConfig = field(default_factory=SupervisedConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    evaluation: EvaluationConfig = field(default_factory=EvaluationConfig)
    cicids: CicidsConfig = field(default_factory=CicidsConfig)


def _resolve(path_str: str) -> Path:
    """يحوّل المسار النسبي إلى مسار مطلق بالنسبة لجذر المشروع."""
    path = Path(path_str)
    return path if path.is_absolute() else PROJECT_ROOT / path


def load_config(path: str | Path | None = None) -> Config:
    """
    يقرأ ملف YAML ويبني منه كائن Config.

    أي مفتاح غير موجود في الملف يأخذ القيمة الافتراضية المعرّفة أعلاه،
    لذلك يمكن كتابة ملف إعدادات صغير يغيّر قيمة واحدة فقط.
    """
    path = Path(path) if path else DEFAULT_CONFIG_PATH
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    paths_raw = raw.get("paths", {})
    return Config(
        seed=raw.get("seed", 42),
        paths=PathsConfig(**{k: _resolve(v) for k, v in paths_raw.items()}),
        data=DataConfig(**raw.get("data", {})),
        supervised=SupervisedConfig(**raw.get("supervised", {})),
        anomaly=AnomalyConfig(**raw.get("anomaly", {})),
        evaluation=EvaluationConfig(**raw.get("evaluation", {})),
        cicids=CicidsConfig(**raw.get("cicids", {})),
    )
