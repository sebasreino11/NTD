import numpy as np
import pandas as pd
import pytest

from ntd.detector import detect


def blob_with_outlier():
    rng = np.random.default_rng(0)
    data = rng.normal(0, 1, size=(200, 3))
    data = np.vstack([data, [[50, 50, 50]]])
    return pd.DataFrame(data, columns=["a", "b", "c"])


def test_outlier_has_top_score_and_is_flagged():
    feats = blob_with_outlier()
    scores, flags = detect(feats, contamination=0.01)
    assert scores.argmax() == 200
    assert flags[200]
    assert flags.dtype == bool


def test_output_lengths_match_input():
    feats = blob_with_outlier()
    scores, flags = detect(feats)
    assert len(scores) == len(flags) == len(feats)


def test_deterministic():
    feats = blob_with_outlier()
    s1, _ = detect(feats)
    s2, _ = detect(feats)
    assert np.array_equal(s1, s2)


@pytest.mark.parametrize("bad", [0, -0.1, 0.51, 1])
def test_invalid_contamination_raises(bad):
    with pytest.raises(ValueError, match="contamination"):
        detect(blob_with_outlier(), contamination=bad)


@pytest.mark.parametrize("kwargs", [
    {"n_estimators": 0}, {"n_estimators": -5},
    {"max_samples": 0}, {"max_samples": 1.5}, {"max_samples": "lots"},
    {"n_jobs": 0},
])
def test_invalid_model_params_raise(kwargs):
    with pytest.raises(ValueError):
        detect(blob_with_outlier(), **kwargs)


def test_same_seed_same_scores_different_seed_different_scores():
    feats = blob_with_outlier()
    a, _ = detect(feats, random_state=1)
    b, _ = detect(feats, random_state=1)
    c, _ = detect(feats, random_state=2)
    assert np.array_equal(a, b)
    assert not np.array_equal(a, c)


def test_custom_model_params_are_accepted():
    scores, flags = detect(blob_with_outlier(), n_estimators=20, max_samples=64, n_jobs=1)
    assert scores.argmax() == 200


@pytest.mark.parametrize("contamination", [0.01, 0.05, 0.5])
def test_flags_exactly_top_fraction(contamination):
    import math
    feats = blob_with_outlier()
    scores, flags = detect(feats, contamination=contamination)
    k = math.ceil(contamination * len(feats))
    assert flags.sum() == k
    assert scores[flags].min() >= scores[~flags].max()


def test_tied_scores_at_the_cut_still_flag_the_full_count():
    rows = np.vstack([np.ones((100, 2)), np.random.default_rng(0).normal(0, 1, (100, 2)) + 9])
    scores, flags = detect(pd.DataFrame(rows), contamination=0.1)
    assert flags.sum() == 20


def test_single_row_does_not_crash():
    scores, flags = detect(pd.DataFrame({"a": [1.0], "b": [2.0]}))
    assert len(scores) == len(flags) == 1


def test_constant_data_does_not_crash():
    feats = pd.DataFrame(np.ones((50, 3)), columns=["a", "b", "c"])
    scores, flags = detect(feats)
    assert len(scores) == 50
    assert np.isfinite(scores).all()
    assert not flags.any()  # all scores identical: no basis to flag any row
