"""Deterministic JSON renderer."""

from __future__ import annotations

import json

from phishlens.models import Report


def render_json(report: Report) -> str:
    return json.dumps(
        report.to_dict(),
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
    )
