"""PhishLens heuristics: identity + header + link + brand detectors.

The collector concatenates detector findings in a stable order. It does NOT
score, rank, weight, or categorize — that is Phase 7.
"""

from __future__ import annotations

from collections.abc import Sequence

from phishlens.data.brands import Brand
from phishlens.models import Finding, ParsedEmail

from .headers_anomaly import detect_header_anomalies
from .identity import detect_identity
from .links_heuristics import detect_links
from .typosquat import detect_brands

__all__ = ["run_brand", "run_identity_link"]


def run_brand(
    parsed: ParsedEmail,
    *,
    brands: Sequence[Brand] | None = None,
) -> list[Finding]:
    """Brand-aware findings (typosquat / tld-swap / combosquat / display spoof)."""
    return detect_brands(parsed, brands=brands)


def run_identity_link(
    parsed: ParsedEmail,
    *,
    brands: Sequence[Brand] | None = None,
) -> list[Finding]:
    """Identity, header-anomaly, link, then brand findings (stable order)."""
    findings: list[Finding] = []
    findings += detect_identity(parsed)
    findings += detect_header_anomalies(parsed)
    findings += detect_links(parsed)
    findings += run_brand(parsed, brands=brands)
    return findings
