import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.pipeline import Pipeline

from netsentinel.features.preprocessing import select_features


def compute_permutation_importance(model, df, n_samples=3000, seed=42):
    """Shuffle one feature at a time and see how much macro-F1 drops."""
    sample = df.sample(n=min(n_samples, len(df)), random_state=seed)
    # wrap preprocessing + classifier so we shuffle the original columns, not one-hot columns
    estimator = Pipeline([("prep", model.preprocessor), ("clf", model.classifier)])
    result = permutation_importance(estimator, select_features(sample, model.spec), sample["category"],
                                    scoring="f1_macro", n_repeats=5, random_state=seed, n_jobs=-1)
    return pd.Series(result.importances_mean, index=model.features).sort_values(ascending=False)
