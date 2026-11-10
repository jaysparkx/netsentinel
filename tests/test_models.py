"""اختبارات النماذج والنظام الهجين والتقييم."""

import numpy as np
import pytest

from netsentinel.data.spec import nsl_kdd_spec
from netsentinel.evaluation.metrics import binary_metrics, evaluate_hybrid
from netsentinel.features.preprocessing import build_preprocessor, select_features
from netsentinel.models.anomaly import build_detector
from netsentinel.models.hybrid import UNKNOWN_ANOMALY, HybridIDS, NormalBaseline
from netsentinel.models.supervised import SUPERVISED_MODELS, build_classifier


@pytest.fixture(scope="module")
def hybrid(train_frame) -> HybridIDS:
    spec = nsl_kdd_spec("full")
    prep = build_preprocessor(spec)
    X = prep.fit_transform(select_features(train_frame, spec))
    normal = (train_frame["is_attack"] == 0).to_numpy()
    clf = build_classifier("random_forest").fit(X, train_frame["category"])
    det = build_detector("isolation_forest").fit(X[normal][:400])
    det.calibrate(X[normal][400:], 99)
    baseline = NormalBaseline.from_frame(select_features(train_frame[normal], spec), spec)
    return HybridIDS(spec, prep, clf, det, baseline)


@pytest.mark.parametrize("name", list(SUPERVISED_MODELS))
def test_every_classifier_trains(train_frame, name):
    spec = nsl_kdd_spec("live")
    prep = build_preprocessor(spec)
    X = prep.fit_transform(select_features(train_frame, spec))
    clf = build_classifier(name).fit(X, train_frame["category"])
    assert set(clf.predict(X)) <= set(train_frame["category"])


@pytest.mark.parametrize("name", ["isolation_forest", "autoencoder"])
def test_detector_scores_attacks_higher(train_frame, name):
    spec = nsl_kdd_spec("full")
    prep = build_preprocessor(spec)
    X = prep.fit_transform(select_features(train_frame, spec))
    normal = (train_frame["is_attack"] == 0).to_numpy()
    det = build_detector(name).fit(X[normal])
    scores = det.score(X)
    assert scores[~normal].mean() > scores[normal].mean()


def test_uncalibrated_detector_refuses_to_predict(train_frame):
    det = build_detector("isolation_forest")
    with pytest.raises(RuntimeError):
        det.predict(np.zeros((2, 3)))


def test_hybrid_predict_columns_and_fusion_rule(hybrid, test_frame):
    pred = hybrid.predict(test_frame)
    assert len(pred) == len(test_frame)
    assert {"final_label", "is_alert", "severity", "anomaly_score"} <= set(pred.columns)
    # قاعدة الدمج: إذا قال المصنِّف هجوم → final = رأيه
    attacks = pred["classifier_label"] != "normal"
    assert (pred.loc[attacks, "final_label"] == pred.loc[attacks, "classifier_label"]).all()
    # إذا قال طبيعي وكان شاذّاً → Unknown-Anomaly
    unknown = (~attacks) & (pred["is_anomaly"] == 1)
    assert (pred.loc[unknown, "final_label"] == UNKNOWN_ANOMALY).all()


def test_hybrid_detects_synthetic_attacks(hybrid, test_frame):
    metrics = evaluate_hybrid(test_frame, hybrid.predict(test_frame))
    assert metrics["hybrid"]["detection_rate"] > 0.9


def test_explain_flags_syn_flood(hybrid, test_frame):
    row = test_frame[test_frame["attack"] == "neptune"].iloc[0]
    features = {r["feature"] for r in hybrid.explain(row)}
    assert features & {"serror_rate", "dst_host_serror_rate", "count", "flag"}


def test_save_and_load_roundtrip(hybrid, test_frame, tmp_path):
    path = tmp_path / "model.joblib"
    hybrid.save(path)
    loaded = HybridIDS.load(path)
    assert (loaded.predict(test_frame)["final_label"] == hybrid.predict(test_frame)["final_label"]).all()


def test_binary_metrics_known_values():
    y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0, 0, 0])
    y_pred = np.array([1, 1, 1, 0, 1, 0, 0, 0, 0, 0])
    m = binary_metrics(y_true, y_pred)
    assert m["detection_rate"] == 0.75        # 3 من 4 هجمات
    assert m["false_alarm_rate"] == round(1 / 6, 4)  # 1 من 6 طبيعي
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (3, 1, 5, 1)


def test_incidents_group_alerts_by_source_target_and_label():
    import pandas as pd
    from netsentinel.alerts import group_incidents

    features = pd.DataFrame({
        "src_ip": ["1.1.1.1"] * 3 + ["2.2.2.2"],
        "dst_ip": ["9.9.9.9"] * 4,
        "dst_port": [22, 23, 80, 80],
    })
    predictions = pd.DataFrame({
        "final_label": ["Probe", "Probe", "Probe", "DoS"],
        "is_alert": [1, 1, 1, 1],
        "severity": ["medium", "medium", "medium", "high"],
        "anomaly_score": [0.1, 0.9, 0.2, 0.5],
        "confidence": [0.8, 0.8, 0.8, 0.9],
    })
    incidents = group_incidents(features, predictions)
    assert len(incidents) == 2
    assert incidents.iloc[0]["final_label"] == "DoS"            # الأخطر أولاً
    scan = incidents[incidents["final_label"] == "Probe"].iloc[0]
    assert (scan["connections"], scan["dst_ports"], scan["representative"]) == (3, 3, 1)


def test_refit_baseline_calibrates_on_shuffled_sample(hybrid, train_frame):
    import copy
    normal = train_frame[train_frame["is_attack"] == 0]
    model = copy.deepcopy(hybrid)
    model.refit_baseline(normal, percentile=99)
    assert model.metadata["baseline_source"] == "custom"
    # الطبيعي نفسه يجب ألا يُنذر إلا نادراً بعد إعادة الضبط
    assert model.predict(normal)["is_anomaly"].mean() < 0.05
