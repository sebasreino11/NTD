"""Synthetic sanity evaluation (not a benchmark).

Labels come from the generator, so these numbers say the detector separates
*these* injected patterns from *this* simulated traffic, nothing more.
Observed on seeds 0-7 when the thresholds were set (see README):
  easy / hard, no hard negatives : ROC-AUC 1.00, recall@k 1.00
  hard negatives added           : ROC-AUC ~0.99, recall@k ~0.5
Legitimate big transfers and long ssh sessions compete with the attacks for
the top ranks; that is a real limitation, so recall@k there has a low bar.
"""
import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

from ntd.detector import detect
from ntd.features import build_features
from ntd.loader import load_conn_log
from tests.synthetic import make_synthetic_log

SEEDS = range(5)


def score_log(tmp_path, seed, **kwargs):
    log = tmp_path / f"conn_{seed}.json"
    injected = make_synthetic_log(log, seed=seed, **kwargs)
    df, skipped = load_conn_log(log)
    assert skipped == 0
    scores, flags = detect(build_features(df))
    labels = np.zeros(len(df), dtype=int)
    labels[injected] = 1
    return scores, flags, labels, injected


def recall_at_k(scores, injected):
    k = len(injected)
    return len(set(np.argsort(-scores)[:k]) & set(injected)) / k


@pytest.mark.parametrize("difficulty", ["easy", "hard"])
def test_clean_background_separates_attacks(tmp_path, difficulty):
    for seed in SEEDS:
        scores, _, labels, injected = score_log(tmp_path, seed, difficulty=difficulty)
        assert roc_auc_score(labels, scores) >= 0.97
        assert recall_at_k(scores, injected) >= 0.9


@pytest.mark.parametrize("difficulty", ["easy", "hard"])
def test_unusual_but_legitimate_traffic_degrades_but_keeps_auc(tmp_path, difficulty):
    for seed in SEEDS:
        scores, _, labels, injected = score_log(
            tmp_path, seed, difficulty=difficulty, hard_negatives=True)
        assert roc_auc_score(labels, scores) >= 0.95
        assert recall_at_k(scores, injected) >= 0.3


def test_clean_traffic_still_flags_contamination_fraction(tmp_path):
    """Documents the tautology: flags are a ranking cut, not a verdict."""
    for seed in SEEDS:
        scores, flags, _, injected = score_log(tmp_path, seed, n_attack=0)
        assert injected == []
        assert flags.sum() == 20  # exactly 1% of 2000 even with no attacks


def test_attack_scores_exceed_the_clean_maximum(tmp_path):
    """Score magnitude carries signal across files (even though flags do not)."""
    for seed in SEEDS:
        clean_scores, _, _, _ = score_log(tmp_path, seed, n_attack=0)
        scores, _, _, injected = score_log(tmp_path, seed)
        assert scores[injected].mean() > clean_scores.max()
