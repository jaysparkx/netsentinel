import logging
import urllib.request

import pandas as pd

from netsentinel.data.schema import NORMAL_LABEL, RAW_COLUMNS, attack_to_category

logger = logging.getLogger(__name__)

NSL_KDD_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
NSL_KDD_FILES = {
    "KDDTrain+": "KDDTrain+.txt",
    "KDDTest+": "KDDTest+.txt",
    "KDDTest-21": "KDDTest-21.txt",
}


def download_nsl_kdd(raw_dir, force=False):
    raw_dir.mkdir(parents=True, exist_ok=True)
    for filename in NSL_KDD_FILES.values():
        target = raw_dir / filename
        if target.exists() and not force:
            logger.info("%s already downloaded", filename)
            continue
        logger.info("downloading %s", filename)
        urllib.request.urlretrieve(NSL_KDD_URL + filename, target)


def load_split(raw_dir, split):
    """Load one NSL-KDD file and add category / is_attack columns."""
    path = raw_dir / NSL_KDD_FILES[split]
    if not path.exists():
        raise FileNotFoundError(f"{path} not found, run: netsentinel download")

    df = pd.read_csv(path, header=None, names=RAW_COLUMNS)
    df["attack"] = df["attack"].str.strip()
    df["category"] = df["attack"].map(attack_to_category)
    df["is_attack"] = (df["attack"] != NORMAL_LABEL).astype(int)
    logger.info("loaded %s: %d rows", split, len(df))
    return df


def mark_novel_attacks(test_df, train_df):
    # attacks in the test set that never appear in training (our "zero-day" set)
    known = set(train_df["attack"].unique())
    test_df = test_df.copy()
    test_df["is_novel"] = (~test_df["attack"].isin(known)).astype(int)
    return test_df
