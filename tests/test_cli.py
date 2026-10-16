import pandas as pd

from ntd.cli import main
from tests.synthetic import make_synthetic_log


def test_analyze_writes_ranked_csv_and_prints_summary(tmp_path, capsys):
    log = tmp_path / "conn.json"
    make_synthetic_log(log)
    out = tmp_path / "nested" / "anomalies.csv"
    code = main(["analyze", str(log), "--out", str(out), "--top", "3"])
    assert code == 0
    written = pd.read_csv(out)
    assert written["flagged"].all()
    assert written["anomaly_score"].is_monotonic_decreasing
    captured = capsys.readouterr().out
    assert "Rows read: 2010" in captured
    assert "Rows valid: 2010" in captured
    assert "Flagged:" in captured
    assert "reasons" in written.columns
    assert (written["reasons"].str.len() > 0).all()
    assert "Top 3" in captured


def test_all_flag_writes_every_row(tmp_path):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, n_normal=100)
    out = tmp_path / "all.csv"
    assert main(["analyze", str(log), "--out", str(out), "--all"]) == 0
    assert len(pd.read_csv(out)) == 110


def test_missing_file_returns_1(tmp_path, capsys):
    code = main(["analyze", str(tmp_path / "nope.json"), "--out", str(tmp_path / "o.csv")])
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_empty_file_returns_1(tmp_path, capsys):
    log = tmp_path / "empty.json"
    log.write_text("")
    assert main(["analyze", str(log), "--out", str(tmp_path / "o.csv")]) == 1
    assert "error:" in capsys.readouterr().err


def test_bad_contamination_returns_1(tmp_path, capsys):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, n_normal=50)
    code = main(["analyze", str(log), "--contamination", "0.9", "--out", str(tmp_path / "o.csv")])
    assert code == 1
    assert "contamination" in capsys.readouterr().err


def test_negative_top_is_rejected(tmp_path, capsys):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, n_normal=50)
    try:
        main(["analyze", str(log), "--top", "-1", "--out", str(tmp_path / "o.csv")])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("expected argparse to reject negative --top")


def test_unwritable_out_returns_1_not_traceback(tmp_path, capsys):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, n_normal=50)
    code = main(["analyze", str(log), "--out", str(tmp_path)])  # a directory
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_out_under_a_regular_file_returns_1(tmp_path, capsys):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, n_normal=50)
    code = main(["analyze", str(log), "--out", str(log / "x.csv")])
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_rows_read_counts_valid_plus_skipped(tmp_path, capsys):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, n_normal=50)
    with log.open("a") as fh:
        fh.write("{broken\n")
        fh.write('{"ts": 1}\n')
    assert main(["analyze", str(log), "--out", str(tmp_path / "o.csv")]) == 0
    out = capsys.readouterr().out
    assert "Rows read: 62" in out and "Rows valid: 60" in out and "Rows skipped: 2" in out


def test_model_flags_are_accepted_and_seed_changes_nothing_when_equal(tmp_path):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, n_normal=100)
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    common = ["analyze", str(log), "--n-estimators", "50", "--max-samples", "64", "--n-jobs", "1", "--seed", "7"]
    assert main(common + ["--out", str(a)]) == 0
    assert main(common + ["--out", str(b)]) == 0
    assert a.read_text() == b.read_text()


def test_invalid_model_flags_are_rejected(tmp_path):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, n_normal=50)
    for bad in (["--n-estimators", "0"], ["--max-samples", "lots"]):
        try:
            main(["analyze", str(log), "--out", str(tmp_path / "o.csv")] + bad)
        except SystemExit as exc:
            assert exc.code == 2
        else:
            raise AssertionError(f"expected argparse to reject {bad}")


def test_max_samples_out_of_range_returns_1(tmp_path, capsys):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, n_normal=50)
    code = main(["analyze", str(log), "--max-samples", "1.5", "--out", str(tmp_path / "o.csv")])
    assert code == 1
    assert "max_samples" in capsys.readouterr().err


def test_by_host_writes_hosts_csv_and_prints_summary(tmp_path, capsys):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, beacon=True)
    hosts = tmp_path / "h" / "hosts.csv"
    code = main(["analyze", str(log), "--out", str(tmp_path / "o.csv"),
                 "--by-host", "--hosts-out", str(hosts)])
    assert code == 0
    written = pd.read_csv(hosts)
    assert written["flagged"].all()
    assert "10.0.0.99" in set(written["id.orig_h"]) or "10.0.0.7" in set(written["id.orig_h"])
    out = capsys.readouterr().out
    assert "Hosts analysed:" in out and "Hosts flagged:" in out


def test_by_host_off_by_default_writes_no_hosts_file(tmp_path):
    log = tmp_path / "conn.json"
    make_synthetic_log(log, n_normal=50)
    hosts = tmp_path / "hosts.csv"
    main(["analyze", str(log), "--out", str(tmp_path / "o.csv"), "--hosts-out", str(hosts)])
    assert not hosts.exists()
