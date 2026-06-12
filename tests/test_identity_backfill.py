"""Phase 4.0 backfill: pin the three Phase-3 identity detectors via synthetic
ParsedEmail objects. No detector logic changed."""

from __future__ import annotations

from phishlens.heuristics.identity import (
    detect_display_domain_mismatch,
    detect_display_embeds_addr,
    detect_returnpath_from_mismatch,
)
from phishlens.models import HeaderSet, ParsedEmail, Severity


def _parsed(
    *,
    from_display: str | None = None,
    from_addr: str | None = None,
    return_path: str | None = None,
) -> ParsedEmail:
    return ParsedEmail(
        headers=HeaderSet(raw={}),
        from_display=from_display,
        from_addr=from_addr,
        reply_to=None,
        return_path=return_path,
        subject=None,
        text_body=None,
        html_body=None,
        links=[],
        attachments=[],
    )


def test_display_embeds_addr() -> None:
    p = _parsed(
        from_display="Support support@evil.test",
        from_addr="billing@example.com",
    )
    findings = detect_display_embeds_addr(p)
    assert [f.id for f in findings] == ["IDENT.DISPLAY_EMBEDS_ADDR"]
    assert findings[0].severity == Severity.HIGH


def test_display_domain_mismatch() -> None:
    p = _parsed(
        from_display="Account at example.com",
        from_addr="alerts@other.test",
    )
    findings = detect_display_domain_mismatch(p)
    assert [f.id for f in findings] == ["IDENT.DISPLAY_DOMAIN_MISMATCH"]
    assert findings[0].severity == Severity.MEDIUM


def test_returnpath_from_mismatch() -> None:
    p = _parsed(
        from_addr="alice@example.com",
        return_path="bounce@bounce.other.test",
    )
    findings = detect_returnpath_from_mismatch(p)
    assert [f.id for f in findings] == ["IDENT.RETURNPATH_FROM_MISMATCH"]
    assert findings[0].severity == Severity.LOW
