"""Command-line entry point: ntd analyze <conn.log.json>."""
import argparse
import sys

from ntd.detector import detect
from ntd.explain import explain
from ntd.features import build_features
from ntd.hosts import analyze_hosts, format_host_summary, write_hosts_csv
from ntd.loader import load_conn_log
from ntd.report import build_results, format_summary, write_csv


def non_negative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {value}")
    return number


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be > 0, got {value}")
    return number


def max_samples_value(value):
    """'auto', a positive int (no dot) or a float in (0, 1]."""
    if value == "auto":
        return value
    try:
        number = int(value) if value.lstrip("+").isdigit() else float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be 'auto', an int or a float, got {value!r}")
    return number


def build_parser():
    parser = argparse.ArgumentParser(prog="ntd", description="Network Threat Detection")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="score a Zeek conn.log (JSON lines)")
    analyze.add_argument("input", help="path to conn.log in JSON-lines format")
    analyze.add_argument("--contamination", type=float, default=0.01,
                         help="fraction of connections to flag, in (0, 0.5] (default 0.01)")
    analyze.add_argument("--out", default="anomalies.csv", help="output CSV path")
    analyze.add_argument("--top", type=non_negative_int, default=10,
                         help="how many flagged connections to print (default 10)")
    analyze.add_argument("--all", action="store_true", dest="include_all",
                         help="write every connection to the CSV, not only flagged ones")
    analyze.add_argument("--n-estimators", type=positive_int, default=100,
                         help="number of trees (default 100)")
    analyze.add_argument("--max-samples", type=max_samples_value, default="auto",
                         help="rows per tree: 'auto', an int, or a float in (0, 1] (default auto)")
    analyze.add_argument("--n-jobs", type=int, default=1,
                         help="parallel jobs, -1 = all cores (default 1)")
    analyze.add_argument("--seed", type=int, default=42, help="random seed (default 42)")
    analyze.add_argument("--by-host", action="store_true",
                         help="also score each source host (scans, beaconing)")
    analyze.add_argument("--hosts-out", default="hosts.csv",
                         help="per-host CSV path used with --by-host (default hosts.csv)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    model = dict(n_estimators=args.n_estimators, max_samples=args.max_samples,
                 n_jobs=args.n_jobs, random_state=args.seed)
    try:
        df, skipped = load_conn_log(args.input)
        features = build_features(df)
        scores, flags = detect(features, contamination=args.contamination, **model)
        rows = features.index if args.include_all else features.index[flags]
        reasons = explain(features, rows=rows)
        host_results = host_warning = None
        if args.by_host:
            host_results, host_warning = analyze_hosts(
                df, contamination=args.contamination,
                flagged_only_reasons=not args.include_all, **model)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    results = build_results(df, scores, flags, reasons)
    try:
        written = write_csv(results, args.out, include_all=args.include_all)
        hosts_written = (write_hosts_csv(host_results, args.hosts_out, include_all=args.include_all)
                         if args.by_host else None)
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 1
    print(format_summary(len(df), skipped, results, args.top))
    print(f"Wrote {written} rows to {args.out}")
    if args.by_host:
        if host_warning:
            print(f"warning: {host_warning}", file=sys.stderr)
        print()
        print(format_host_summary(host_results, args.top))
        print(f"Wrote {hosts_written} rows to {args.hosts_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
