"""Per-source-host aggregation for `ntd analyze --by-host`.

One row per `id.orig_h`, scored by its own Isolation Forest. It sees scans
(many distinct ports/hosts) and periodic callbacks (beaconing) that a
per-connection view cannot. It does not use time windows.
"""
from pathlib import Path

import numpy as np
import pandas as pd

from ntd.detector import detect
from ntd.explain import explain

MIN_EVENTS_PER_PAIR = 5
NEUTRAL_CV = 1.0   # used when no (dst, port) pair has enough events
CV_CAP = 5.0
MIN_HOSTS_WARNING = 10
HOST_RAW_COLUMNS = ["n_conns", "n_dst_hosts", "n_dst_ports", "bytes_sent", "min_pair_iat_cv"]
HOST_FEATURE_COLUMNS = HOST_RAW_COLUMNS  # same names; counts/bytes are log1p'd in features
HOST_RESULT_COLUMNS = ["id.orig_h"] + HOST_RAW_COLUMNS + ["host_score", "flagged", "reasons"]


def _pair_cv(ts):
    """Coefficient of variation of the gaps between events, or NaN if too few events."""
    if len(ts) < MIN_EVENTS_PER_PAIR:
        return np.nan
    gaps = np.diff(np.sort(ts.to_numpy(dtype=float)))
    mean = gaps.mean()
    if mean <= 0:
        return np.nan
    return gaps.std() / mean


def build_host_table(df):
    grouped = df.groupby("id.orig_h")
    table = pd.DataFrame({
        "n_conns": grouped.size(),
        "n_dst_hosts": grouped["id.resp_h"].nunique(),
        "n_dst_ports": grouped["id.resp_p"].nunique(),
        "bytes_sent": grouped["orig_bytes"].sum(),
    })
    pair_cv = (
        df.groupby(["id.orig_h", "id.resp_h", "id.resp_p"])["ts"].apply(_pair_cv)
    )
    min_cv = pair_cv.groupby(level=0).min()
    table["min_pair_iat_cv"] = min_cv.reindex(table.index).fillna(NEUTRAL_CV).clip(upper=CV_CAP)
    return table


def host_features(table):
    feats = table.copy().astype(float)
    for col in ["n_conns", "n_dst_hosts", "n_dst_ports", "bytes_sent"]:
        feats[col] = np.log1p(feats[col])
    return feats[HOST_FEATURE_COLUMNS]


def analyze_hosts(df, contamination=0.01, flagged_only_reasons=True, **model_params):
    """Return (results, warning). `model_params` go straight to `detect`."""
    table = build_host_table(df)
    feats = host_features(table)
    scores, flags = detect(feats, contamination=contamination, **model_params)
    rows = feats.index[flags] if flagged_only_reasons else feats.index
    reasons = explain(feats, rows=rows, continuous=HOST_FEATURE_COLUMNS, categorical=[])
    results = table.copy()
    results["host_score"] = scores
    results["flagged"] = flags
    results["reasons"] = reasons.reindex(results.index).fillna("")
    results = results.sort_values("host_score", ascending=False, kind="stable")
    results = results.reset_index()
    warning = None
    if len(table) < MIN_HOSTS_WARNING:
        warning = (f"only {len(table)} source hosts: per-host scores have little statistical power")
    return results[HOST_RESULT_COLUMNS], warning


def write_hosts_csv(results, path, include_all=False):
    rows = results if include_all else results[results["flagged"]]
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows.to_csv(path, index=False)
    return len(rows)


def format_host_summary(results, top):
    flagged = results[results["flagged"]]
    lines = [f"Hosts analysed: {len(results)}", f"Hosts flagged: {len(flagged)}"]
    if flagged.empty or top <= 0:
        return "\n".join(lines)
    shown = flagged.head(top).copy()
    shown["host_score"] = shown["host_score"].map(lambda v: f"{v:.4f}")
    shown["min_pair_iat_cv"] = shown["min_pair_iat_cv"].map(lambda v: f"{v:.2f}")
    lines.append(f"Top {len(shown)} most suspicious source hosts:")
    lines.append(shown.drop(columns=["flagged"]).to_string(index=False))
    return "\n".join(lines)
