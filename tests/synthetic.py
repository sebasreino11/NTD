"""Generate a Zeek-style conn.log with a known port scan and exfil injected.

`difficulty="easy"` injects blatant attacks; `"hard"` injects subtler ones.
`hard_negatives=True` adds legitimate-but-unusual traffic (big downloads, long
ssh sessions) that is NOT labelled as an attack. `beacon=True` adds a host
calling home at a fixed interval and `wide_scan=True` adds a host probing 80
ports of one server (both are meant for `--by-host`; neither is in the returned labels).
"""
import json
import sys
from pathlib import Path

import numpy as np


def _rec(ts, src, sport, dst, dport, proto, duration, ob, rb, op, rp, state):
    return {
        "ts": float(ts), "id.orig_h": src, "id.orig_p": int(sport),
        "id.resp_h": dst, "id.resp_p": int(dport), "proto": proto,
        "duration": float(duration), "orig_bytes": int(ob), "resp_bytes": int(rb),
        "orig_pkts": int(op), "resp_pkts": int(rp), "conn_state": state,
    }


BEACON_HOST = "10.0.0.55"
WIDE_SCANNER_HOST = "10.0.0.98"
SCANNER_HOST = "10.0.0.99"
EXFIL_HOST = "10.0.0.7"


def make_synthetic_log(path, n_normal=2000, seed=0, difficulty="easy",
                       hard_negatives=False, beacon=False, wide_scan=False, n_attack=None):
    """Write the log and return the row indices of the injected attacks.

    `n_attack` (default 5) is how many scan rows and how many exfil rows to inject;
    an explicit 0 injects none, which gives a clean control file.
    """
    if difficulty not in ("easy", "hard"):
        raise ValueError(f"difficulty must be 'easy' or 'hard', got {difficulty!r}")
    n_attack = 5 if n_attack is None else n_attack
    rng = np.random.default_rng(seed)
    records = []
    servers = ["10.0.1.10", "10.0.1.11", "10.0.1.12"]
    for i in range(n_normal):
        dport = int(rng.choice([80, 443, 53, 22, 8080]))
        records.append(_rec(
            ts=1_700_000_000 + i,
            src=f"10.0.0.{rng.integers(1, 51)}", sport=rng.integers(32768, 60000),
            dst=str(rng.choice(servers)), dport=dport,
            proto="udp" if dport == 53 else "tcp",
            duration=rng.exponential(2.0),
            ob=rng.lognormal(6, 1), rb=rng.lognormal(8, 1.2),
            op=rng.integers(3, 60), rp=rng.integers(3, 80), state="SF",
        ))
    if hard_negatives:  # unusual but legitimate: not labelled as attacks
        for k in range(20):  # big software/backup download
            records.append(_rec(
                1_700_005_000 + k, f"10.0.0.{rng.integers(1, 51)}", rng.integers(32768, 60000),
                str(rng.choice(servers)), 443, "tcp", rng.uniform(60, 180),
                rng.lognormal(7, 0.5), rng.lognormal(17, 0.5),
                rng.integers(50, 200), rng.integers(20_000, 60_000), "SF",
            ))
        for k in range(20):  # long interactive ssh session
            records.append(_rec(
                1_700_006_000 + k, f"10.0.0.{rng.integers(1, 51)}", rng.integers(32768, 60000),
                str(rng.choice(servers)), 22, "tcp", rng.uniform(1800, 5400),
                rng.lognormal(9.5, 0.5), rng.lognormal(10, 0.5),
                rng.integers(500, 3000), rng.integers(500, 3000), "SF",
            ))
    injected = []
    for k in range(n_attack):  # port scan: one source, many ports, no payload
        injected.append(len(records))
        if difficulty == "easy":
            rec = _rec(1_700_010_000 + k, SCANNER_HOST, 40000 + k, "10.0.1.10", 20 + k,
                       "tcp", 0.0, 0, 0, 1, 0, "S0")
        else:  # slow scan: small probes, spread out, near-normal sizes
            rec = _rec(1_700_010_000 + k * 300, SCANNER_HOST, 40000 + k, "10.0.1.10", 20 + k,
                       "tcp", 0.3, 150, 0, 3, 0, "S0")
        records.append(rec)
    for k in range(n_attack):  # exfil: big upload to an external host
        injected.append(len(records))
        if difficulty == "easy":
            rec = _rec(1_700_020_000 + k, EXFIL_HOST, 45000 + k, "203.0.113.9", 443,
                       "tcp", 600.0, 500_000_000, 2000, 400_000, 3000, "SF")
        else:  # moderate upload (300 KB), shorter
            rec = _rec(1_700_020_000 + k, EXFIL_HOST, 45000 + k, "203.0.113.9", 443,
                       "tcp", 20.0, 300_000, 3000, 250, 60, "SF")
        records.append(rec)
    if wide_scan:  # one source sweeping many ports: the per-host view's target
        for k in range(80):
            records.append(_rec(
                1_700_030_000 + k, WIDE_SCANNER_HOST, 41000 + k, "10.0.1.11", 1000 + k,
                "tcp", 0.0, 0, 0, 1, 0, "S0",
            ))
    if beacon:  # fixed-interval callbacks, normal-looking sizes, one per 50s
        for k in range(40):
            records.append(_rec(
                1_700_000_000 + k * 50, BEACON_HOST, 50000 + k, "198.51.100.7", 443,
                "tcp", 1.0, 300, 500, 6, 6, "SF",
            ))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return injected


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "tests/data/sample_conn.json"
    idx = make_synthetic_log(out, beacon=True, wide_scan=True)
    print(f"wrote {out}; injected rows: {idx}")
