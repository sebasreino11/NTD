"""Isolation Forest scoring."""
import math

import numpy as np
from sklearn.ensemble import IsolationForest


def _validate(contamination, n_estimators, max_samples, n_jobs):
    if not 0 < contamination <= 0.5:
        raise ValueError(f"contamination must be in (0, 0.5], got {contamination}")
    if not isinstance(n_estimators, int) or n_estimators <= 0:
        raise ValueError(f"n_estimators must be a positive integer, got {n_estimators}")
    if isinstance(max_samples, str):
        if max_samples != "auto":
            raise ValueError(f"max_samples must be 'auto', a positive int or a float in (0, 1], got {max_samples!r}")
    elif isinstance(max_samples, int):
        if max_samples <= 0:
            raise ValueError(f"max_samples must be positive, got {max_samples}")
    elif not 0 < max_samples <= 1:
        raise ValueError(f"max_samples float must be in (0, 1], got {max_samples}")
    if not isinstance(n_jobs, int) or n_jobs == 0:
        raise ValueError(f"n_jobs must be a non-zero integer (-1 = all cores), got {n_jobs}")


def detect(features, contamination=0.01, random_state=42, n_estimators=100,
           max_samples="auto", n_jobs=1):
    """Fit on `features` and score the same rows. Higher score = more suspicious.

    `flags` marks exactly the top ceil(contamination * n) rows by score (ties broken
    by file order); it is a ranking cut, not a verdict (see README). It is done by
    rank because the forest's own threshold skips rows tied at the cut, so heavy
    ties (e.g. a scan of identical probes) would flag far fewer than expected.
    If every score is identical nothing is flagged.
    """
    _validate(contamination, n_estimators, max_samples, n_jobs)
    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=max_samples,
        contamination=contamination,
        random_state=random_state,
        n_jobs=n_jobs,
    )
    model.fit(features)
    scores = -model.score_samples(features)
    flags = np.zeros(len(scores), dtype=bool)
    if scores.max() > scores.min():
        k = max(1, math.ceil(contamination * len(scores)))
        flags[np.argsort(-scores, kind="stable")[:k]] = True
    return scores, flags
