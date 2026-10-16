import numpy as np
import pandas as pd

from ntd.report import ID_COLUMNS, build_results, format_summary, write_csv


def make_df(n=4):
    return pd.DataFrame({
        "ts": np.arange(n, dtype=float),
        "id.orig_h": [f"10.0.0.{i}" for i in range(n)],
        "id.orig_p": [1000 + i for i in range(n)],
        "id.resp_h": ["10.0.1.1"] * n,
        "id.resp_p": [443] * n,
        "proto": ["tcp"] * n,
        "extra": ["x"] * n,
    })


def make_results():
    scores = np.array([0.1, 0.9, 0.5, 0.7])
    flags = np.array([False, True, False, True])
    return build_results(make_df(), scores, flags)


def test_build_results_sorted_desc_with_original_index():
    res = make_results()
    assert list(res.columns) == ID_COLUMNS + ["anomaly_score", "flagged", "reasons"]
    assert list(res["anomaly_score"]) == [0.9, 0.7, 0.5, 0.1]
    assert list(res.index) == [1, 3, 2, 0]


def test_write_csv_anomalies_only_by_default(tmp_path):
    out = tmp_path / "a.csv"
    n = write_csv(make_results(), out)
    written = pd.read_csv(out)
    assert n == 2
    assert len(written) == 2
    assert written["flagged"].all()
    assert list(written.columns) == ID_COLUMNS + ["anomaly_score", "flagged", "reasons"]


def test_write_csv_include_all(tmp_path):
    out = tmp_path / "a.csv"
    assert write_csv(make_results(), out, include_all=True) == 4
    assert len(pd.read_csv(out)) == 4


def test_write_csv_creates_missing_parent_dir(tmp_path):
    out = tmp_path / "deep" / "er" / "a.csv"
    write_csv(make_results(), out)
    assert out.is_file()


def test_summary_counts_and_top_table():
    text = format_summary(rows_valid=4, skipped=2, results=make_results(), top=10)
    assert "Rows read: 6" in text
    assert "Rows valid: 4" in text
    assert "Rows skipped: 2" in text
    assert "Flagged: 2 (50.00%)" in text
    assert "10.0.0.1" in text and "10.0.0.3" in text
    assert "10.0.0.0" not in text  # not an anomaly, so not listed even though top > flagged


def test_summary_respects_top():
    text = format_summary(rows_valid=4, skipped=0, results=make_results(), top=1)
    assert "10.0.0.1" in text
    assert "10.0.0.3" not in text


def test_summary_when_nothing_flagged():
    df = make_df()
    res = build_results(df, np.array([0.1, 0.2, 0.3, 0.4]), np.zeros(4, dtype=bool))
    text = format_summary(rows_valid=4, skipped=0, results=res, top=10)
    assert "Flagged: 0" in text
    assert "No connections flagged" in text


def test_summary_top_zero_does_not_claim_nothing_flagged():
    text = format_summary(rows_valid=4, skipped=0, results=make_results(), top=0)
    assert "Flagged: 2" in text
    assert "No connections flagged" not in text
    assert "10.0.0.1" not in text


def test_reasons_default_empty_and_partial_reasons_fill_blanks():
    import pandas as pd
    base = build_results(make_df(), np.array([0.1, 0.9, 0.5, 0.7]), np.array([False, True, False, True]))
    assert (base["reasons"] == "").all()
    reasons = pd.Series({1: "orig_bytes +9.0"})
    res = build_results(make_df(), np.array([0.1, 0.9, 0.5, 0.7]), np.array([False, True, False, True]), reasons)
    assert res.loc[1, "reasons"] == "orig_bytes +9.0"
    assert res.loc[3, "reasons"] == ""


def test_summary_table_shows_reasons():
    import pandas as pd
    res = build_results(make_df(), np.array([0.1, 0.9, 0.5, 0.7]), np.array([False, True, False, True]),
                        pd.Series({1: "orig_bytes +9.0", 3: "duration +4.0"}))
    text = format_summary(rows_valid=4, skipped=0, results=res, top=5)
    assert "orig_bytes +9.0" in text
