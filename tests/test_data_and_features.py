"""اختبارات المخطّط والمعالجة المسبقة."""

import numpy as np
import pytest

from netsentinel.data.loader import mark_novel_attacks
from netsentinel.data.schema import ATTACK_CATEGORY, FEATURE_PROFILES, attack_to_category
from netsentinel.data.spec import nsl_kdd_spec
from netsentinel.features.preprocessing import build_preprocessor, select_features


def test_attack_categories_cover_all_five_classes():
    assert set(ATTACK_CATEGORY.values()) == {"DoS", "Probe", "R2L", "U2R"}
    assert attack_to_category("neptune") == "DoS"
    assert attack_to_category("normal") == "normal"


def test_unknown_attack_raises():
    with pytest.raises(ValueError):
        attack_to_category("not_a_real_attack")


def test_live_profile_has_no_content_features():
    assert "num_failed_logins" not in FEATURE_PROFILES["live"]
    assert "root_shell" not in FEATURE_PROFILES["live"]
    assert len(FEATURE_PROFILES["live"]) == 28
    assert "num_outbound_cmds" not in FEATURE_PROFILES["full"]   # عمود ثابت محذوف


@pytest.mark.parametrize("profile", ["full", "live"])
def test_preprocessor_output_is_finite_and_scaled(train_frame, profile):
    spec = nsl_kdd_spec(profile)
    prep = build_preprocessor(spec)
    X = prep.fit_transform(select_features(train_frame, spec))
    assert X.shape[0] == len(train_frame)
    assert np.isfinite(X).all()


def test_preprocessor_ignores_unseen_categories(train_frame):
    spec = nsl_kdd_spec("full")
    prep = build_preprocessor(spec)
    prep.fit(select_features(train_frame, spec))
    unseen = train_frame.head(3).copy()
    unseen["service"] = "brand_new_service"
    X = prep.transform(select_features(unseen, spec))
    assert X.shape[0] == 3   # لا يتعطّل مع خدمة لم يرها


def test_mark_novel_attacks(train_frame, test_frame):
    test = test_frame.copy()
    test.loc[0, "attack"] = "mailbomb"
    marked = mark_novel_attacks(test, train_frame)
    assert marked.loc[0, "is_novel"] == 1
    assert marked["is_novel"].sum() == 1
