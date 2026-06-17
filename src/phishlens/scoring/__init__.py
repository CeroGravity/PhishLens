"""Transparent weighted scoring. Pure, deterministic — no ML, no clock."""

from __future__ import annotations

from collections.abc import Iterable

from phishlens.models import Finding, RiskCategory

from .config import CATEGORY_THRESHOLDS, SCORE_CAP, SEVERITY_WEIGHTS

__all__ = ["categorize", "score"]


def score(findings: Iterable[Finding]) -> int:
    """Sum of severity weights, capped at SCORE_CAP."""
    total = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return min(total, SCORE_CAP)


def categorize(value: int) -> RiskCategory:
    """Map a score to its RiskCategory using the documented thresholds."""
    for minimum, category in CATEGORY_THRESHOLDS:
        if value >= minimum:
            return category
    return RiskCategory.LOW
