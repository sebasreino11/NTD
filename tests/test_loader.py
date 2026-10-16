import json

import pytest

from ntd.loader import load_conn_log

GOOD = {
    "ts": 1.0, "id.orig_h": "10.0.0.1", "id.orig_p": 50000,
    "id.resp_h": "10.0.0.2", "id.resp_p": 443, "proto": "tcp",
    "duration": 1.5, "orig_bytes": 100, "resp_bytes": 200,
    "orig_pkts": 4, "resp_pkts": 5, "conn_state": "SF",
}


def write_lines(tmp_path, lines):
    path = tmp_path / "conn.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_loads_flat_dotted_keys(tmp_path):
    path = write_lines(tmp_path, [json.dumps(GOOD), json.dumps(GOOD)])
    df, skipped = load_conn_log(path)
    assert len(df) == 2
    assert skipped == 0
    assert df.loc[0, "id.resp_p"] == 443
    assert df.loc[0, "orig_bytes"] == 100


def test_loads_nested_id_object(tmp_path):
    nested = {
        "ts": 1.0,
        "id": {"orig_h": "10.0.0.1", "orig_p": 1234, "resp_h": "10.0.0.2", "resp_p": 80},
        "proto": "tcp", "duration": 2.0, "orig_bytes": 10, "resp_bytes": 20,
        "orig_pkts": 1, "resp_pkts": 1,
    }
    df, skipped = load_conn_log(write_lines(tmp_path, [json.dumps(nested)]))
    assert skipped == 0
    assert df.loc[0, "id.orig_h"] == "10.0.0.1"
    assert df.loc[0, "id.resp_p"] == 80


def test_dash_null_negative_and_missing_numeric_become_zero(tmp_path):
    rec = dict(GOOD)
    rec["duration"] = "-"
    rec["orig_bytes"] = None
    rec["orig_pkts"] = -5
    del rec["resp_bytes"]  # column absent entirely
    df, skipped = load_conn_log(write_lines(tmp_path, [json.dumps(rec)]))
    assert skipped == 0
    row = df.loc[0]
    assert row["duration"] == 0
    assert row["orig_bytes"] == 0
    assert row["orig_pkts"] == 0
    assert row["resp_bytes"] == 0
    assert not df.isna().any().any()


def test_blank_lines_ignored_malformed_and_incomplete_counted(tmp_path):
    missing_dst = dict(GOOD)
    del missing_dst["id.resp_h"]
    dash_proto = dict(GOOD, proto="-")
    lines = [
        json.dumps(GOOD),
        "",
        "   ",
        "{not json",
        json.dumps(missing_dst),
        json.dumps(dash_proto),
        "[1, 2, 3]",
        json.dumps(GOOD),
    ]
    df, skipped = load_conn_log(write_lines(tmp_path, lines))
    assert len(df) == 2
    assert skipped == 4  # malformed, missing field, "-" proto, non-object
    assert list(df.index) == [0, 1]


def test_non_numeric_resp_port_is_skipped_not_imputed(tmp_path):
    lines = [json.dumps(GOOD), json.dumps(dict(GOOD, **{"id.resp_p": "abc"}))]
    df, skipped = load_conn_log(write_lines(tmp_path, lines))
    assert len(df) == 1
    assert skipped == 1


def test_port_zero_skipped_for_tcp_and_udp_but_kept_for_icmp(tmp_path):
    lines = [
        json.dumps(GOOD),
        json.dumps(dict(GOOD, **{"id.resp_p": 0})),
        json.dumps(dict(GOOD, **{"id.resp_p": 0, "proto": "udp"})),
        json.dumps(dict(GOOD, **{"id.resp_p": 0, "proto": "icmp"})),
    ]
    df, skipped = load_conn_log(write_lines(tmp_path, lines))
    assert skipped == 2
    assert list(df["proto"]) == ["tcp", "icmp"]
    assert df.loc[1, "id.resp_p"] == 0


def test_port_above_65535_is_skipped(tmp_path):
    lines = [json.dumps(GOOD), json.dumps(dict(GOOD, **{"id.resp_p": 70000}))]
    df, skipped = load_conn_log(write_lines(tmp_path, lines))
    assert len(df) == 1
    assert skipped == 1


def test_missing_orig_port_is_imputed_to_zero(tmp_path):
    rec = dict(GOOD)
    del rec["id.orig_p"]
    df, skipped = load_conn_log(write_lines(tmp_path, [json.dumps(rec)]))
    assert skipped == 0
    assert df.loc[0, "id.orig_p"] == 0


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_conn_log(tmp_path / "nope.json")


def test_empty_file_raises(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("\n\n")
    with pytest.raises(ValueError, match="empty"):
        load_conn_log(path)


def test_no_valid_rows_raises(tmp_path):
    path = write_lines(tmp_path, ["{bad", json.dumps({"ts": 1})])
    with pytest.raises(ValueError, match="No valid"):
        load_conn_log(path)
