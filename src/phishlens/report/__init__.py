"""Report builder. Aggregates findings + auth into a deterministic Report.

generated_at is injected (no implicit clock) so reports are reproducible.
"""

from __future__ import annotations

from phishlens.models import AuthResult, Finding, Report
from phishlens.scoring import categorize, score
from phishlens.scoring.config import SEVERITY_WEIGHTS

__all__ = ["build_report", "render_json", "render_markdown", "sort_findings"]


def _finding_sort_key(f: Finding) -> tuple[int, str, str]:
    # Severity descending (negate weight), then id asc, then evidence asc.
    return (-SEVERITY_WEIGHTS[f.severity], f.id, f.evidence or "")


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Stable total order: severity desc, id asc, evidence asc."""
    return sorted(findings, key=_finding_sort_key)


def build_report(
    target: str,
    mode: str,
    findings: list[Finding],
    auth: AuthResult | None,
    *,
    generated_at: str,
) -> Report:
    ordered = sort_findings(findings)
    total = score(ordered)
    return Report(
        target=target,
        mode=mode,
        category=categorize(total),
        score=total,
        findings=ordered,
        auth=auth,
        generated_at=generated_at,
    )


# Re-export renderers for convenience.
from .json_renderer import render_json  # noqa: E402
from .markdown_renderer import render_markdown  # noqa: E402
