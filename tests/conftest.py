"""
بيانات اختبار صناعية صغيرة بنفس أعمدة NSL-KDD.

الاختبارات لا تعتمد على ملفات NSL-KDD الحقيقية (حتى تعمل بسرعة وفي أي مكان)،
بل نصنع جدولاً عشوائياً لكن "منطقياً": الهجمات DoS لها flag=S0 وcount عالٍ...
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from netsentinel.data.schema import ALL_FEATURES, attack_to_category

ATTACK_PROFILES = {
    "normal": dict(flag="SF", service="http", count=(1, 20), serror=0.0, src_bytes=(200, 5000)),
    "neptune": dict(flag="S0", service="private", count=(200, 500), serror=1.0, src_bytes=(0, 1)),
    "portsweep": dict(flag="REJ", service="other", count=(1, 5), serror=0.0, src_bytes=(0, 1)),
    "guess_passwd": dict(flag="SF", service="telnet", count=(1, 3), serror=0.0, src_bytes=(100, 200)),
    "rootkit": dict(flag="SF", service="ftp_data", count=(1, 3), serror=0.0, src_bytes=(1000, 3000)),
}


def make_frame(counts: dict[str, int], seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for attack, n in counts.items():
        prof = ATTACK_PROFILES[attack]
        for _ in range(n):
            row = dict.fromkeys(ALL_FEATURES, 0)
            row.update(
                protocol_type="tcp", service=prof["service"], flag=prof["flag"],
                src_bytes=int(rng.integers(*prof["src_bytes"])) if prof["src_bytes"][1] > 1 else 0,
                dst_bytes=int(rng.integers(0, 8000)) if attack == "normal" else 0,
                count=int(rng.integers(*prof["count"])),
                serror_rate=prof["serror"], dst_host_serror_rate=prof["serror"],
                rerror_rate=1.0 if prof["flag"] == "REJ" else 0.0,
                num_failed_logins=int(attack == "guess_passwd") * int(rng.integers(1, 5)),
                root_shell=int(attack == "rootkit"),
                logged_in=int(attack in {"normal", "rootkit"}),
                same_srv_rate=float(rng.uniform(0.8, 1.0)),
                dst_host_count=int(rng.integers(1, 255)),
            )
            row["srv_count"] = row["count"]
            row["attack"] = attack
            rows.append(row)
    df = pd.DataFrame(rows).sample(frac=1, random_state=seed).reset_index(drop=True)
    df["category"] = df["attack"].map(attack_to_category)
    df["is_attack"] = (df["attack"] != "normal").astype(int)
    return df


@pytest.fixture(scope="session")
def train_frame() -> pd.DataFrame:
    return make_frame({"normal": 600, "neptune": 200, "portsweep": 100, "guess_passwd": 60, "rootkit": 40})


@pytest.fixture(scope="session")
def test_frame() -> pd.DataFrame:
    return make_frame({"normal": 150, "neptune": 50, "portsweep": 30, "guess_passwd": 15, "rootkit": 10}, seed=1)
