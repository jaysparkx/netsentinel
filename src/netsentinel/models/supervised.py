from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier

CLASSIFIER_NAMES = ["random_forest", "hist_gradient_boosting", "logistic_regression", "mlp"]


def build_classifier(name, seed=42):
    # class_weight="balanced" because U2R has only ~50 rows vs ~67k normal
    if name == "random_forest":
        return RandomForestClassifier(n_estimators=300, min_samples_leaf=1,
                                      class_weight="balanced_subsample", n_jobs=-1, random_state=seed)
    if name == "hist_gradient_boosting":
        return HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, class_weight="balanced",
                                              early_stopping=True, random_state=seed)
    if name == "logistic_regression":
        return LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed)
    if name == "mlp":
        # MLPClassifier has no class_weight option
        return MLPClassifier(hidden_layer_sizes=(128, 64), early_stopping=True, max_iter=200, random_state=seed)
    raise ValueError(f"unknown classifier: {name}")
