"""CIC-IDS2017 experiments.

random:   mix all days, 30% test (what most papers do, every attack type is in training)
temporal: train on Mon-Wed, test on Thu-Fri, so every test attack is new to the model
"""

import logging

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from netsentinel.data.cicids import cicids_spec, load_cicids
from netsentinel.data.loader import mark_novel_attacks
from netsentinel.pipeline.train import evaluate_model, train_hybrid

logger = logging.getLogger(__name__)

TRAIN_DAYS = ["monday", "tuesday", "wednesday"]
TEST_DAYS = ["thursday", "friday"]


def balanced_sample(df, normal_n, attack_cap, seed):
    # the data is too big to train on everything: take normal_n normal rows and
    # at most attack_cap rows of each attack (rare attacks are kept whole)
    normal = df[df["is_attack"] == 0]
    parts = [normal.sample(n=min(normal_n, len(normal)), random_state=seed)]
    for _, group in df[df["is_attack"] == 1].groupby("attack"):
        parts.append(group.sample(n=min(attack_cap, len(group)), random_state=seed))
    return pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)


def _run(cfg, run, train_pool, test_df):
    c = cfg.cicids
    train_df = balanced_sample(train_pool, c.normal_train_samples, c.attack_cap_per_type, cfg.seed)
    logger.info("[%s] training sample: %s", run, train_df["attack"].value_counts().to_dict())
    test_df = mark_novel_attacks(test_df, train_df)
    model, selection = train_hybrid(cfg, cicids_spec(run), train_df, run)
    return evaluate_model(cfg, model, run, selection, {"test": test_df})


def run_random_split(cfg, data):
    pool, test = train_test_split(data, test_size=cfg.cicids.random_test_size,
                                  stratify=data["attack"], random_state=cfg.seed)
    return _run(cfg, "cicids2017_random", pool, test)


def run_temporal_split(cfg, data):
    pool = data[data["day"].isin(TRAIN_DAYS)]
    test = data[data["day"].isin(TEST_DAYS)]
    return _run(cfg, "cicids2017_temporal", pool, test)


def run_cicids(cfg, experiments=None):
    from netsentinel.pipeline.report import write_report

    np.random.seed(cfg.seed)
    data = load_cicids(cfg.paths.raw_dir)
    logger.info("CIC-IDS2017: %d flows %s", len(data), data["category"].value_counts().to_dict())

    runners = {"random": run_random_split, "temporal": run_temporal_split}
    results = {}
    for name in experiments or list(runners):
        res = runners[name](cfg, data)
        results[res["run"]] = res
    path = write_report(cfg, results, "RESULTS_CICIDS2017.md", "NetSentinel results - CIC-IDS2017")
    logger.info("done, report: %s", path)
    return results
