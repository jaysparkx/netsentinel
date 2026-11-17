import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler


def signed_log1p(x):
    # like log1p but also works for negative values (some CIC columns are -1)
    return np.sign(x) * np.log1p(np.abs(x))


def build_preprocessor(spec):
    """One-hot for text columns, log + scale for skewed ones, scale for the rest.
    It is fitted on the training data only."""
    regular = [f for f in spec.features if f not in spec.categorical and f not in spec.skewed]
    log_scale = Pipeline([
        ("log", FunctionTransformer(signed_log1p, feature_names_out="one-to-one")),
        ("scale", StandardScaler()),
    ])
    parts = [
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), spec.categorical),
        ("skewed", log_scale, spec.skewed),
        ("num", StandardScaler(), regular),
    ]
    parts = [p for p in parts if p[2]]  # skip empty groups
    return ColumnTransformer(parts, remainder="drop", verbose_feature_names_out=True)


def select_features(df, spec):
    missing = [c for c in spec.features if c not in df.columns]
    if missing:
        raise ValueError(f"missing columns for {spec.name}/{spec.profile}: {missing}")
    return df[spec.features]
