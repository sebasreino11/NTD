import math

import pandas as pd

from ntd.detector import detect
from ntd.features import build_features
from ntd.loader import load_conn_log
from tests.synthetic import make_synthetic_log


def test_injected_attacks_rank_in_top_one_percent(tmp_path):
    """Smoke test only: blatant attacks on clean traffic, one seed.

    Real evidence lives in test_evaluation.py (metrics, hard negatives, control).
    """
    log = tmp_path / "conn.json"
    injected = make_synthetic_log(log)
    df, skipped = load_conn_log(log)
    assert skipped == 0
    scores, _ = detect(build_features(df))
    ranked = pd.Series(scores, index=df.index).sort_values(ascending=False)
    cutoff = max(1, math.ceil(len(df) * 0.01))
    top = set(ranked.index[:cutoff])
    assert set(injected) <= top
