"""PhishLens heuristics: identity + header + link + brand detectors.

The collector concatenates detector findings in a stable order. It does NOT
score, rank, weight, or categorize — that is Phase 7.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date

from phishlens.auth.dkim_verify import DnsFunc, verify_dkim
from phishlens.data.brands import Brand
from phishlens.enrich.domain_age import find_newly_registered
from phishlens.enrich.rdap import RdapClient
from phishlens.models import Finding, ParsedEmail

from .headers_anomaly import detect_header_anomalies
from .identity import detect_identity
from .links_heuristics import detect_links
from .typosquat import detect_brands

__all__ = ["run_brand", "run_identity_link", "run_online_enrichment"]


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


def run_online_enrichment(
    parsed: ParsedEmail,
    *,
    online: bool = False,
    rdap_client: RdapClient | None = None,
    now: date | None = None,
    raw_bytes: bytes | None = None,
    dnsfunc: DnsFunc | None = None,
) -> list[Finding]:
    """Network-gated findings (domain-age, DKIM crypto). Offline -> [].

    All network is injectable. When online is False, returns [] and makes no
    calls — the offline collector path (run_identity_link) is unaffected.
    """
    if not online:
        return []
    findings: list[Finding] = []
    if rdap_client is not None and now is not None:
        findings += find_newly_registered(
            parsed, online=True, client=rdap_client, now=now
        )
    if raw_bytes is not None:
        findings += verify_dkim(raw_bytes, online=True, dnsfunc=dnsfunc)
    return findings
