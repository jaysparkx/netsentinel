"""اختبارات دعم CIC-IDS2017 (بدون الحاجة لتنزيل البيانات الحقيقية)."""

import numpy as np
import pandas as pd

from netsentinel.data.cicids import ATTACK_CATEGORY, CLASS_NAMES, _clean_label, cicids_features, cicids_spec
from netsentinel.features.preprocessing import build_preprocessor, select_features, signed_log1p
from netsentinel.pipeline.cicids_experiments import balanced_sample


def test_clean_label_fixes_broken_encoding():
    assert _clean_label("Web Attack � XSS") == "Web Attack - XSS"
    assert _clean_label("Web Attack ï¿½ Brute Force") == "Web Attack - Brute Force"
    assert _clean_label(" BENIGN ") == "BENIGN"


def test_every_category_is_a_known_class():
    assert set(ATTACK_CATEGORY.values()) <= set(CLASS_NAMES)


def test_feature_list_excludes_port_and_constant_columns():
    features = cicids_features()
    assert len(features) == 68
    assert "Destination Port" not in features          # منع "الطريق المختصر"
    assert "Fwd Avg Bulk Rate" not in features         # عمود صفري دائماً


def test_signed_log1p_handles_negative_values():
    out = signed_log1p(np.array([-1.0, 0.0, 1.0, 1e9]))
    assert np.isfinite(out).all()
    assert out[0] == -out[2]


def test_cicids_preprocessor_on_random_flows():
    spec = cicids_spec("test")
    rng = np.random.default_rng(0)
    df = pd.DataFrame(rng.exponential(1000, size=(50, len(spec.features))), columns=spec.features)
    df["Init_Win_bytes_forward"] = -1                  # قيمة سالبة حقيقية في البيانات
    X = build_preprocessor(spec).fit_transform(select_features(df, spec))
    assert X.shape == (50, 68) and np.isfinite(X).all()


def test_balanced_sample_caps_large_attacks_and_keeps_rare_ones():
    df = pd.DataFrame({
        "attack": ["BENIGN"] * 100 + ["DoS Hulk"] * 50 + ["Heartbleed"] * 3,
        "is_attack": [0] * 100 + [1] * 53,
    })
    sample = balanced_sample(df, normal_n=40, attack_cap=10, seed=0)
    counts = sample["attack"].value_counts()
    assert (counts["BENIGN"], counts["DoS Hulk"], counts["Heartbleed"]) == (40, 10, 3)
