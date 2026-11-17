import warnings

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPRegressor


class AnomalyDetector:
    """Trained on normal traffic only. Higher score = more unusual."""

    def __init__(self):
        self.threshold_ = None

    def calibrate(self, X_normal, percentile=99.0):
        # threshold at the 99th percentile of normal scores -> about 1% false alarms
        self.threshold_ = float(np.percentile(self.score(X_normal), percentile))
        return self.threshold_

    def predict(self, X):
        if self.threshold_ is None:
            raise RuntimeError("call calibrate() first")
        return (self.score(X) > self.threshold_).astype(int)


class IsolationForestDetector(AnomalyDetector):
    def __init__(self, n_estimators=300, seed=42):
        super().__init__()
        self.model = IsolationForest(n_estimators=n_estimators, contamination="auto",
                                     n_jobs=-1, random_state=seed)

    def fit(self, X_normal):
        self.model.fit(X_normal)
        return self

    def score(self, X):
        return -self.model.score_samples(X)  # sklearn gives higher values for normal points


class AutoencoderDetector(AnomalyDetector):
    """MLP that learns to rebuild its input through an 8-unit bottleneck.
    Bad reconstruction (high MSE) means the connection doesn't look normal."""

    def __init__(self, hidden_layers=(64, 16, 8, 16, 64), epochs=60, seed=42):
        super().__init__()
        # fixed 60 epochs: with early_stopping it stopped after ~13 and detected almost nothing
        self.model = MLPRegressor(hidden_layer_sizes=hidden_layers, activation="relu",
                                  early_stopping=False, max_iter=epochs, random_state=seed)

    def fit(self, X_normal):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            self.model.fit(X_normal, X_normal)
        return self

    def score(self, X):
        rebuilt = self.model.predict(X)
        return np.mean((X - rebuilt) ** 2, axis=1)


def build_detector(name, seed=42):
    if name == "isolation_forest":
        return IsolationForestDetector(seed=seed)
    if name == "autoencoder":
        return AutoencoderDetector(seed=seed)
    raise ValueError(f"unknown detector: {name}")
