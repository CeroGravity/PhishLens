"""PhishLens heuristics: identity + header + link detectors.

The collector concatenates detector findings in a stable order. It does NOT
score, rank, weight, or categorize — that is Phase 6.
"""

from __future__ import annotations

from phishlens.models import Finding, ParsedEmail

from .headers_anomaly import detect_header_anomalies
from .identity import detect_identity
from .links_heuristics import detect_links

__all__ = ["run_identity_link"]


def run_identity_link(parsed: ParsedEmail) -> list[Finding]:
    """Concatenate identity, header-anomaly, and link findings (stable order)."""
    findings: list[Finding] = []
    findings += detect_identity(parsed)
    findings += detect_header_anomalies(parsed)
    findings += detect_links(parsed)
    return findings
