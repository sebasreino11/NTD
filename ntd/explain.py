"""Human-readable reasons for a connection's score.

This describes how far a row sits from the file's typical values (robust
z-scores); it is not the Isolation Forest's internal decision path.
"""
import numpy as np
import pandas as pd

from ntd.features import CONTINUOUS_COLUMNS, PORT_COLUMNS

MAD_TO_SIGMA = 1.4826
SCALE_FLOOR = 0.1  # log-space floor so sparse columns (many exact zeros) don't explode
MIN_ABS_Z = 3.0
RARE_PORT_SHARE = 0.05
NO_REASON = "no strong single-feature deviation"


def robust_z(features, continuous=CONTINUOUS_COLUMNS):
    """(x - median) / (1.4826 * MAD) for the continuous columns, with a scale floor."""
    cont = features[list(continuous)]
    median = cont.median()
    mad = (cont - median).abs().median() * MAD_TO_SIGMA
    return (cont - median) / mad.clip(lower=SCALE_FLOOR)


def explain(features, top_n=3, rows=None, continuous=CONTINUOUS_COLUMNS, categorical=PORT_COLUMNS):
    """Return a Series of 'feature +z; ...' strings, indexed like `rows` (default: all).

    Statistics are always computed on the full `features`; `rows` only limits
    which rows get a text, so callers can skip unflagged rows on big files.
    """
    z = robust_z(features, continuous)
    shares = features[list(categorical)].mean() if categorical else pd.Series(dtype=float)
    index = features.index if rows is None else pd.Index(rows)
    z_sel = z.loc[index]
    port_sel = features.loc[index, list(categorical)]

    texts = []
    for idx in index:
        zr = z_sel.loc[idx]
        notable = zr[zr.abs() >= MIN_ABS_Z]
        notable = notable.reindex(notable.abs().sort_values(ascending=False).index)
        parts = [f"{name} {value:+.1f}" for name, value in notable.items()]
        for col in categorical:
            if port_sel.loc[idx, col] == 1 and shares[col] < RARE_PORT_SHARE:
                parts.append(f"rare port class ({col.removeprefix('port_')}, {100 * shares[col]:.1f}% of rows)")
        texts.append("; ".join(parts[:top_n]) if parts else NO_REASON)
    return pd.Series(texts, index=index, dtype=object)
