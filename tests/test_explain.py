import numpy as np
import pandas as pd

from ntd.explain import NO_REASON, explain, robust_z
from ntd.features import FEATURE_COLUMNS


def make_features(n=200, seed=0):
    rng = np.random.default_rng(seed)
    data = {c: rng.normal(5, 1, n) for c in FEATURE_COLUMNS}
    feats = pd.DataFrame(data)
    feats["port_wellknown"] = 1.0
    feats["port_registered"] = 0.0
    feats["port_ephemeral"] = 0.0
    return feats


def test_outlier_feature_listed_first_with_positive_sign():
    feats = make_features()
    feats.loc[10, "orig_bytes"] = 60.0
    text = explain(feats).loc[10]
    assert text.startswith("orig_bytes +")


def test_typical_row_has_no_strong_reason():
    assert explain(make_features()).loc[0] == NO_REASON


def test_constant_column_does_not_produce_inf_or_nan():
    feats = make_features()
    feats["duration"] = 0.0
    assert np.isfinite(robust_z(feats).to_numpy()).all()
    feats.loc[3, "duration"] = 4.0
    assert "duration +" in explain(feats).loc[3]


def test_rare_port_class_is_reported():
    feats = make_features()
    feats.loc[5, ["port_wellknown", "port_ephemeral"]] = [0.0, 1.0]
    assert "rare port class (ephemeral" in explain(feats).loc[5]


def test_top_n_is_respected():
    feats = make_features()
    feats.loc[1, ["duration", "orig_bytes", "resp_bytes", "orig_pkts"]] = 80.0
    parts = explain(feats, top_n=2).loc[1].split("; ")
    assert len(parts) == 2


def test_rows_subset_and_index_preserved():
    feats = make_features()
    feats.index = range(100, 300)
    out = explain(feats, rows=[105, 250])
    assert list(out.index) == [105, 250]
