"""Auditable, tunable scoring configuration. Single source of truth.

Transparent weighted addition — no ML, no hidden magic.
"""

from __future__ import annotations

from phishlens.models import RiskCategory, Severity

# Severity weights.
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 4,
    Severity.HIGH: 10,
    Severity.CRITICAL: 20,
}

# Maximum total score.
SCORE_CAP = 100

# Category thresholds, evaluated as: the highest band whose minimum the score
# meets. 0–3 LOW, 4–9 MEDIUM, 10–19 HIGH, 20+ CRITICAL.
# Ordered high -> low for lookup.
CATEGORY_THRESHOLDS: tuple[tuple[int, RiskCategory], ...] = (
    (20, RiskCategory.CRITICAL),
    (10, RiskCategory.HIGH),
    (4, RiskCategory.MEDIUM),
    (0, RiskCategory.LOW),
)
