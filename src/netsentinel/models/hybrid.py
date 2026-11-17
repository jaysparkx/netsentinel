import joblib
import numpy as np
import pandas as pd

from netsentinel.data.schema import NORMAL_LABEL
from netsentinel.features.preprocessing import select_features, signed_log1p

UNKNOWN_ANOMALY = "Unknown-Anomaly"

SEVERITY = {
    NORMAL_LABEL: "none",
    "Probe": "medium",
    UNKNOWN_ANOMALY: "medium",
    "DoS": "high",
    "R2L": "high",
    "U2R": "critical",
    # CIC-IDS2017 classes
    "PortScan": "medium",
    "DDoS": "high",
    "BruteForce": "high",
    "WebAttack": "high",
    "Bot": "critical",
    "Infiltration": "critical",
    "Heartbleed": "critical",
}


def _numeric_part(df, spec):
    # numeric columns with the same log transform as the preprocessor
    numeric = df.drop(columns=spec.categorical).astype(float)
    numeric[spec.skewed] = signed_log1p(numeric[spec.skewed])
    return numeric


class NormalBaseline:
    """Mean/std of each feature on normal traffic, used to explain alerts."""

    def __init__(self, mean, std, category_freq=None):
        self.mean = mean
        self.std = std
        self.category_freq = category_freq or {}

    @classmethod
    def from_frame(cls, X_normal, spec):
        numeric = _numeric_part(X_normal, spec)
        freqs = {c: X_normal[c].value_counts(normalize=True) for c in spec.categorical}
        return cls(numeric.mean(), numeric.std().replace(0, 1e-6), freqs)


class HybridIDS:
    def __init__(self, spec, preprocessor, classifier, detector, baseline, metadata=None):
        self.spec = spec
        self.preprocessor = preprocessor
        self.classifier = classifier
        self.detector = detector
        self.baseline = baseline
        self.metadata = metadata or {}

    @property
    def profile(self):
        return self.spec.profile

    @property
    def features(self):
        return self.spec.features

    def transform(self, df):
        return self.preprocessor.transform(select_features(df, self.spec))

    def predict(self, df):
        X = self.transform(df)
        proba = self.classifier.predict_proba(X)
        clf_label = self.classifier.classes_[proba.argmax(axis=1)]
        score = self.detector.score(X)
        is_anomaly = score > self.detector.threshold_

        # classifier says attack -> keep its label
        # classifier says normal but the detector disagrees -> Unknown-Anomaly
        final = np.where(clf_label != NORMAL_LABEL, clf_label,
                         np.where(is_anomaly, UNKNOWN_ANOMALY, NORMAL_LABEL))
        return pd.DataFrame({
            "classifier_label": clf_label,
            "confidence": proba.max(axis=1).round(4),
            "anomaly_score": score.round(6),
            "is_anomaly": is_anomaly.astype(int),
            "final_label": final,
            "is_alert": (final != NORMAL_LABEL).astype(int),
            "severity": pd.Series(final).map(SEVERITY).to_numpy(),
        }, index=df.index)

    def explain(self, row, top_k=5):
        """Features of one connection that are furthest from normal (z-score)."""
        row_df = select_features(row.to_frame().T, self.spec)
        numeric = _numeric_part(row_df, self.spec).iloc[0]
        # min std so a feature that never changed in normal traffic doesn't give a huge z
        std = self.baseline.std.clip(lower=0.05)
        z = ((numeric - self.baseline.mean) / std).clip(-99, 99).dropna()

        reasons = []
        for feat in z.abs().sort_values(ascending=False).index[:top_k]:
            if abs(z[feat]) >= 2:
                reasons.append({"feature": feat, "value": row[feat], "z_score": round(float(z[feat]), 2),
                                "description": self.spec.describe(feat)})
        for feat, freq in self.baseline.category_freq.items():
            share = float(freq.get(row[feat], 0.0))
            if share < 0.01:
                reasons.append({"feature": feat, "value": row[feat], "z_score": None,
                                "description": f"{self.spec.describe(feat)}, rare in normal traffic ({share:.2%})"})
        return reasons

    def refit_baseline(self, df_normal, percentile=99.0, seed=42):
        """Retrain the anomaly detector on normal traffic from your own network."""
        X = self.transform(df_normal)
        # shuffle first, otherwise all the start-of-capture rows end up in the training part
        order = np.random.default_rng(seed).permutation(len(X))
        split = int(len(X) * 0.8)
        self.detector.fit(X[order[:split]])
        self.detector.calibrate(X[order[split:]], percentile)
        self.baseline = NormalBaseline.from_frame(select_features(df_normal, self.spec), self.spec)
        self.metadata["baseline_source"] = "custom"

    def save(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path):
        model = joblib.load(path)
        if not isinstance(model, HybridIDS):
            raise TypeError(f"{path} is not a HybridIDS model")
        return model
