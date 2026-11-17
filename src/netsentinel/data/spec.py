from dataclasses import dataclass, field


@dataclass(frozen=True)
class DatasetSpec:
    """Describes a dataset so the same code works for NSL-KDD and CIC-IDS2017."""
    name: str
    profile: str
    features: list
    categorical: list
    skewed: list            # columns that get a log transform
    class_names: list
    descriptions: dict = field(default_factory=dict)

    def describe(self, feature):
        return self.descriptions.get(feature, feature)


def nsl_kdd_spec(profile):
    from netsentinel.data import schema

    features = schema.FEATURE_PROFILES[profile]
    return DatasetSpec(
        name="NSL-KDD",
        profile=profile,
        features=features,
        categorical=[f for f in features if f in schema.CATEGORICAL_FEATURES],
        skewed=[f for f in features if f in schema.SKEWED_FEATURES],
        class_names=schema.CLASS_NAMES,
        descriptions=schema.FEATURE_DESCRIPTIONS,
    )
