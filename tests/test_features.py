import numpy as np
import pandas as pd

from ntd.features import FEATURE_COLUMNS, build_features, port_bucket


def make_df(**overrides):
    row = {
        "duration": 1.0, "orig_bytes": 100.0, "resp_bytes": 300.0,
        "orig_pkts": 4.0, "resp_pkts": 6.0, "id.resp_p": 443.0,
    }
    row.update(overrides)
    return pd.DataFrame([row])


def test_columns_and_order():
    feats = build_features(make_df())
    assert list(feats.columns) == FEATURE_COLUMNS
    assert "proto" not in feats.columns
    assert "conn_state" not in feats.columns


def test_log1p_applied_to_counts():
    feats = build_features(make_df())
    assert feats.loc[0, "orig_bytes"] == np.log1p(100.0)
    assert feats.loc[0, "duration"] == np.log1p(1.0)


def test_bytes_ratio():
    feats = build_features(make_df(orig_bytes=100.0, resp_bytes=49.0))
    assert feats.loc[0, "bytes_ratio"] == np.log1p(100.0 / 50.0)


def test_port_bucket_boundaries():
    ports = pd.Series([0, 1023, 1024, 49151, 49152, 65535])
    assert list(port_bucket(ports)) == [0, 0, 1, 1, 2, 2]


def test_nine_features_with_one_hot_port_columns():
    assert len(FEATURE_COLUMNS) == 9
    assert FEATURE_COLUMNS[-3:] == ["port_wellknown", "port_registered", "port_ephemeral"]


def test_port_one_hot_boundaries_and_exactly_one_active():
    ports = [0, 1023, 1024, 49151, 49152, 65535]
    df = pd.concat([make_df(**{"id.resp_p": float(p)}) for p in ports], ignore_index=True)
    port_cols = build_features(df)[["port_wellknown", "port_registered", "port_ephemeral"]]
    assert (port_cols.sum(axis=1) == 1).all()
    assert list(port_cols.to_numpy().argmax(axis=1)) == [0, 0, 1, 1, 2, 2]


def test_all_zero_row_is_finite():
    df = make_df(duration=0.0, orig_bytes=0.0, resp_bytes=0.0,
                 orig_pkts=0.0, resp_pkts=0.0, **{"id.resp_p": 0.0})
    feats = build_features(df)
    assert np.isfinite(feats.to_numpy()).all()


def test_index_preserved():
    df = make_df()
    df.index = [7]
    assert list(build_features(df).index) == [7]
