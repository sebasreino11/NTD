"""Build, save and summarise detection results."""
from pathlib import Path

ID_COLUMNS = ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"]
RESULT_COLUMNS = ID_COLUMNS + ["anomaly_score", "flagged", "reasons"]


def build_results(df, scores, flags, reasons=None):
    """Rank connections by score. `reasons` may cover only some rows (others get '')."""
    results = df[ID_COLUMNS].copy()
    results["anomaly_score"] = scores
    results["flagged"] = flags
    if reasons is None:
        results["reasons"] = ""
    else:
        results["reasons"] = reasons.reindex(results.index).fillna("")
    return results.sort_values("anomaly_score", ascending=False, kind="stable")


def write_csv(results, path, include_all=False):
    rows = results if include_all else results[results["flagged"]]
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows.to_csv(path, index=False)
    return len(rows)


def format_counts(rows_valid, skipped, flagged, label="Rows"):
    """Shared count lines. `read` = valid + skipped (blank lines are not counted)."""
    pct = 100.0 * flagged / rows_valid if rows_valid else 0.0
    return [
        f"{label} read: {rows_valid + skipped}",
        f"{label} valid: {rows_valid}",
        f"{label} skipped: {skipped}",
        f"Flagged: {flagged} ({pct:.2f}%) - top fraction by score, not a verdict",
    ]


def format_summary(rows_valid, skipped, results, top):
    flagged = results[results["flagged"]]
    lines = format_counts(rows_valid, skipped, len(flagged))
    if flagged.empty:
        lines.append("No connections flagged.")
        return "\n".join(lines)
    if top <= 0:
        return "\n".join(lines)
    shown = flagged.head(top).copy()
    shown["anomaly_score"] = shown["anomaly_score"].map(lambda s: f"{s:.4f}")
    lines.append(f"Top {len(shown)} most suspicious connections:")
    lines.append(shown.drop(columns=["flagged"]).to_string(index=False))
    return "\n".join(lines)
