"""Sender-identity spoofing detectors. Each returns list[Finding].

Pure, offline, strings only. Intrinsic severities are set here; final
weighting/aggregation is Phase 6.
"""

from __future__ import annotations

import re

from phishlens.models import Finding, ParsedEmail, Severity
from phishlens.util.domains import registrable_domain

# Email-address-like token inside a display name, e.g. "Foo <a@b.com>" or
# bare "support@b.com".
_ADDR_TOKEN = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Bare domain-like token (no @), e.g. "secure-example.com".
_DOMAIN_TOKEN = re.compile(r"\b(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}\b")


def _from_domain(parsed: ParsedEmail) -> str | None:
    return registrable_domain(parsed.from_addr) if parsed.from_addr else None


def detect_display_embeds_addr(parsed: ParsedEmail) -> list[Finding]:
    if not parsed.from_display:
        return []
    from_dom = _from_domain(parsed)
    if from_dom is None:
        return []
    for m in _ADDR_TOKEN.finditer(parsed.from_display):
        token = m.group(0)
        token_dom = registrable_domain(token)
        if token_dom is not None and token_dom != from_dom:
            return [
                Finding(
                    id="IDENT.DISPLAY_EMBEDS_ADDR",
                    title="Display name embeds a foreign email address",
                    severity=Severity.HIGH,
                    reason=(
                        "Display name contains an email address whose domain "
                        "differs from the actual From address domain."
                    ),
                    evidence=f"display={token!r} ({token_dom}) vs from={from_dom}",
                )
            ]
    return []


def detect_display_domain_mismatch(parsed: ParsedEmail) -> list[Finding]:
    if not parsed.from_display:
        return []
    from_dom = _from_domain(parsed)
    if from_dom is None:
        return []
    # Skip tokens that are part of an embedded address (handled above).
    masked = _ADDR_TOKEN.sub(" ", parsed.from_display)
    for m in _DOMAIN_TOKEN.finditer(masked):
        token = m.group(0)
        token_dom = registrable_domain(token)
        if token_dom is not None and token_dom != from_dom:
            return [
                Finding(
                    id="IDENT.DISPLAY_DOMAIN_MISMATCH",
                    title="Display name contains a mismatched domain",
                    severity=Severity.MEDIUM,
                    reason=(
                        "Display name references a domain that differs from "
                        "the actual From address domain."
                    ),
                    evidence=f"display={token!r} ({token_dom}) vs from={from_dom}",
                )
            ]
    return []


def detect_replyto_offdomain(parsed: ParsedEmail) -> list[Finding]:
    if not parsed.reply_to or not parsed.from_addr:
        return []
    reply_dom = registrable_domain(parsed.reply_to)
    from_dom = _from_domain(parsed)
    if reply_dom is None or from_dom is None or reply_dom == from_dom:
        return []
    return [
        Finding(
            id="IDENT.REPLYTO_OFFDOMAIN",
            title="Reply-To is on a different domain than From",
            severity=Severity.MEDIUM,
            reason="Reply-To domain differs from the From address domain.",
            evidence=f"reply_to={reply_dom} vs from={from_dom}",
        )
    ]


def detect_returnpath_from_mismatch(parsed: ParsedEmail) -> list[Finding]:
    if not parsed.return_path or not parsed.from_addr:
        return []
    rp_dom = registrable_domain(parsed.return_path)
    from_dom = _from_domain(parsed)
    if rp_dom is None or from_dom is None or rp_dom == from_dom:
        return []
    return [
        Finding(
            id="IDENT.RETURNPATH_FROM_MISMATCH",
            title="Return-Path domain differs from From",
            severity=Severity.LOW,
            reason=(
                "Return-Path (envelope sender) domain differs from the From "
                "address domain. Structural cross-check; overlaps SPF alignment."
            ),
            evidence=f"return_path={rp_dom} vs from={from_dom}",
        )
    ]


# Phase 4: brand-keyword display spoofing (display says "PayPal" but the
# domain isn't paypal) — needs the brand list. Not implemented here.


def detect_identity(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    findings += detect_display_embeds_addr(parsed)
    findings += detect_display_domain_mismatch(parsed)
    findings += detect_replyto_offdomain(parsed)
    findings += detect_returnpath_from_mismatch(parsed)
    return findings
