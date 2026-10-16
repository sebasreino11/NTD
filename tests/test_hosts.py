import numpy as np
import pandas as pd
import pytest

from ntd.hosts import (HOST_RESULT_COLUMNS, NEUTRAL_CV, analyze_hosts, build_host_table,
                       format_host_summary)
from ntd.loader import load_conn_log
from tests.synthetic import BEACON_HOST, WIDE_SCANNER_HOST, make_synthetic_log


def conns(rows):
    base = {"id.resp_h": "10.9.9.9", "id.resp_p": 443, "orig_bytes": 100.0}
    return pd.DataFrame([{**base, **r} for r in rows])


def test_table_aggregates_per_source():
    df = conns([
        {"id.orig_h": "a", "ts": 1.0, "id.resp_h": "x", "id.resp_p": 80, "orig_bytes": 10.0},
        {"id.orig_h": "a", "ts": 2.0, "id.resp_h": "y", "id.resp_p": 80, "orig_bytes": 20.0},
        {"id.orig_h": "a", "ts": 3.0, "id.resp_h": "y", "id.resp_p": 443, "orig_bytes": 30.0},
        {"id.orig_h": "b", "ts": 1.0},
    ])
    t = build_host_table(df)
    assert t.loc["a", "n_conns"] == 3
    assert t.loc["a", "n_dst_hosts"] == 2
    assert t.loc["a", "n_dst_ports"] == 2
    assert t.loc["a", "bytes_sent"] == 60
    assert t.loc["b", "n_conns"] == 1


def test_pairs_with_fewer_than_five_events_get_neutral_cv():
    df = conns([{"id.orig_h": "a", "ts": float(i)} for i in range(4)])
    assert build_host_table(df).loc["a", "min_pair_iat_cv"] == NEUTRAL_CV


def test_periodic_pair_has_low_cv_and_irregular_pair_high_cv():
    periodic = [{"id.orig_h": "beacon", "ts": 60.0 * i} for i in range(10)]
    rng = np.random.default_rng(0)
    irregular = [{"id.orig_h": "human", "ts": float(t)}
                 for t in np.cumsum(rng.exponential(30, 10))]
    t = build_host_table(conns(periodic + irregular))
    assert t.loc["beacon", "min_pair_iat_cv"] < 0.01
    assert t.loc["human", "min_pair_iat_cv"] > 0.3


def test_scanner_and_beacon_rank_at_the_top_on_synthetic_log(tmp_path):
    log = tmp_path / "c.json"
    make_synthetic_log(log, beacon=True, wide_scan=True)
    df, _ = load_conn_log(log)
    results, warning = analyze_hosts(df, contamination=0.1)
    assert warning is None
    assert list(results.columns) == HOST_RESULT_COLUMNS
    top = list(results["id.orig_h"].head(4))
    assert WIDE_SCANNER_HOST in top
    assert BEACON_HOST in top
    assert results["host_score"].is_monotonic_decreasing


def test_few_hosts_emit_a_warning():
    df = conns([{"id.orig_h": f"h{i % 3}", "ts": float(i)} for i in range(30)])
    _, warning = analyze_hosts(df, contamination=0.1)
    assert warning and "3 source hosts" in warning


def test_host_summary_lists_only_flagged():
    df = conns([{"id.orig_h": f"h{i % 12}", "ts": float(i)} for i in range(120)])
    results, _ = analyze_hosts(df, contamination=0.1)
    text = format_host_summary(results, top=3)
    assert "Hosts analysed: 12" in text
    assert "Hosts flagged:" in text


def test_model_params_are_validated():
    df = conns([{"id.orig_h": f"h{i % 12}", "ts": float(i)} for i in range(120)])
    with pytest.raises(ValueError):
        analyze_hosts(df, n_estimators=0)
