"""Load a Zeek conn.log written as JSON lines.

Guarantees: only the columns NTD uses are kept; rows missing a required field
(or with an invalid destination port) are skipped and counted; optional numeric
fields that are absent, "-", null or negative become 0.
"""
import json
from pathlib import Path

import pandas as pd

REQUIRED = ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto"]
NUMERIC = [
    "id.orig_p", "id.resp_p", "duration",
    "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
]
COLUMNS = REQUIRED + [c for c in NUMERIC if c not in REQUIRED] + ["conn_state"]
PORT_REQUIRED_PROTOS = {"tcp", "udp"}  # ICMP stores type/code in the port fields, 0 is valid


def _field(rec, name):
    """Read a flat dotted key ("id.resp_p") or its nested form ({"id": {"resp_p": ..}})."""
    if name in rec:
        return rec[name]
    parent, _, child = name.partition(".")
    nested = rec.get(parent)
    if child and isinstance(nested, dict):
        return nested.get(child)
    return None


def _read_columns(path):
    columns = {name: [] for name in COLUMNS}
    skipped = 0
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if not isinstance(rec, dict):
                skipped += 1
                continue
            for name in COLUMNS:
                columns[name].append(_field(rec, name))
    return columns, skipped


def load_conn_log(path):
    """Return (DataFrame, skipped_count). See the module docstring for guarantees."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")

    columns, skipped = _read_columns(path)
    df = pd.DataFrame(columns)

    if df.empty and skipped == 0:
        raise ValueError("Input file is empty")

    present = df[REQUIRED].notna().all(axis=1)
    not_dash = ~df[REQUIRED].isin(["-", ""]).any(axis=1)
    resp_port = pd.to_numeric(df["id.resp_p"], errors="coerce")
    port_ok = resp_port.between(0, 65535)
    proto = df["proto"].astype(str).str.lower()
    port_zero = proto.isin(PORT_REQUIRED_PROTOS) & (resp_port == 0)
    valid = present & not_dash & port_ok & ~port_zero
    skipped += int((~valid).sum())
    df = df[valid].reset_index(drop=True)

    if df.empty:
        raise ValueError("No valid connection records found in input")

    for col in NUMERIC:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).clip(lower=0)

    return df, skipped
