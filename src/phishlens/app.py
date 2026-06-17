"""Analysis orchestration. Pure of argparse and of the clock.

The CLI calls these functions, supplying generated_at and (online) the real
RDAP client / dnsfunc. Tests drive the same seams with fakes. Strings only:
no message URL is ever fetched, resolved, or expanded.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date

from phishlens import auth
from phishlens.auth.dkim_verify import DnsFunc
from phishlens.data.brands import Brand
from phishlens.enrich.rdap import RdapClient
from phishlens.heuristics import (
    run_brand,
    run_identity_link,
    run_online_enrichment,
)
from phishlens.heuristics.auth_findings import auth_to_findings
from phishlens.heuristics.links_heuristics import detect_links
from phishlens.ingest.eml import load_eml
from phishlens.models import Finding, HeaderSet, Link, ParsedEmail, Report
from phishlens.report import build_report


def _online_findings(
    parsed: ParsedEmail,
    *,
    online: bool,
    rdap_client: RdapClient | None,
    now: date | None,
    raw_bytes: bytes | None,
    dnsfunc: DnsFunc | None,
) -> list[Finding]:
    if not online:
        return []
    return run_online_enrichment(
        parsed,
        online=True,
        rdap_client=rdap_client,
        now=now,
        raw_bytes=raw_bytes,
        dnsfunc=dnsfunc,
    )


def analyze_email(
    path: str,
    *,
    generated_at: str,
    online: bool = False,
    brands: Sequence[Brand] | None = None,
    rdap_client: RdapClient | None = None,
    dnsfunc: DnsFunc | None = None,
    now: date | None = None,
) -> Report:
    """Full pipeline for a .eml file."""
    parsed = load_eml(path)
    auth_result = auth.analyze(parsed, online=online, resolver=None)

    findings = run_identity_link(parsed, brands=brands)
    findings += auth_to_findings(auth_result)

    raw_bytes: bytes | None = None
    if online:
        with open(path, "rb") as fh:
            raw_bytes = fh.read()
    findings += _online_findings(
        parsed,
        online=online,
        rdap_client=rdap_client,
        now=now,
        raw_bytes=raw_bytes,
        dnsfunc=dnsfunc,
    )

    return build_report(
        target=path,
        mode="eml",
        findings=findings,
        auth=auth_result,
        generated_at=generated_at,
    )


def analyze_url(
    url: str,
    *,
    generated_at: str,
    online: bool = False,
    brands: Sequence[Brand] | None = None,
    rdap_client: RdapClient | None = None,
    now: date | None = None,
) -> Report:
    """Analyze a bare URL string. Never fetched/resolved/expanded.

    A minimal ParsedEmail (one link, no sender) drives the link + brand
    detectors; sender-dependent detectors skip gracefully (from_addr is None).
    """
    parsed = ParsedEmail(
        headers=HeaderSet(raw={}),
        from_display=None,
        from_addr=None,
        reply_to=None,
        return_path=None,
        subject=None,
        text_body=None,
        html_body=None,
        links=[Link(href=url, anchor_text=None, source="text")],
        attachments=[],
    )

    # URL mode runs only the URL-relevant detectors: link heuristics and
    # brand/typosquat. Sender/header/auth detectors are skipped (no sender).
    findings = detect_links(parsed)
    findings += run_brand(parsed, brands=brands)
    # URL mode has no message bytes -> no DKIM verify; domain-age still applies.
    findings += _online_findings(
        parsed,
        online=online,
        rdap_client=rdap_client,
        now=now,
        raw_bytes=None,
        dnsfunc=None,
    )

    return build_report(
        target=url,
        mode="url",
        findings=findings,
        auth=None,
        generated_at=generated_at,
    )
