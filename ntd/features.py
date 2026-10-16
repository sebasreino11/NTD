"""Turn loaded connections into the numeric matrix the model sees."""
import numpy as np
import pandas as pd

LOG_COLUMNS = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]
PORT_COLUMNS = ["port_wellknown", "port_registered", "port_ephemeral"]
CONTINUOUS_COLUMNS = LOG_COLUMNS + ["bytes_ratio"]
FEATURE_COLUMNS = CONTINUOUS_COLUMNS + PORT_COLUMNS


def port_bucket(port):
    """0 = well-known (<1024), 1 = registered (<49152), 2 = ephemeral."""
    return np.select([port < 1024, port < 49152], [0, 1], default=2)


def build_features(df):
    feats = pd.DataFrame(index=df.index)
    for col in LOG_COLUMNS:
        feats[col] = np.log1p(df[col].astype(float))
    feats["bytes_ratio"] = np.log1p(df["orig_bytes"] / (df["resp_bytes"] + 1))
    bucket = port_bucket(df["id.resp_p"])
    # One-hot: the three classes are categories, not points on a scale.
    for code, col in enumerate(PORT_COLUMNS):
        feats[col] = (bucket == code).astype(float)
    return feats[FEATURE_COLUMNS]
