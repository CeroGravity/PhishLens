"""Phase 7 report builder + renderer tests. Offline, injected generated_at."""

from __future__ import annotations

import json
from pathlib import Path

from phishlens import auth
from phishlens.heuristics import run_identity_link
from phishlens.heuristics.auth_findings import auth_to_findings
from phishlens.ingest.eml import load_eml
from phishlens.models import (
    AuthResult,
    Finding,
    HeaderSet,
    Link,
    ParsedEmail,
    RiskCategory,
    Severity,
)
from phishlens.report import (
    build_report,
    render_json,
    render_markdown,
    sort_findings,
)

FIXTURES = Path(__file__).parent / "fixtures"
GEN = "2024-06-01T00:00:00Z"


def _full_findings(name: str) -> tuple[list[Finding], AuthResult]:
    p = load_eml(str(FIXTURES / name))
    a = auth.analyze(p)
    return run_identity_link(p) + auth_to_findings(a), a


# --- end to end ------------------------------------------------------------


def test_benign_low() -> None:
    finds, a = _full_findings("benign_plain.eml")
    r = build_report("benign_plain.eml", "offline", finds, a, generated_at=GEN)
    assert r.category == RiskCategory.LOW
    assert r.score == 0


def test_link_mismatch_high() -> None:
    finds, a = _full_findings("link_mismatch.eml")
    r = build_report("link_mismatch.eml", "offline", finds, a, generated_at=GEN)
    assert r.category == RiskCategory.HIGH
    # HREF_TEXT_MISMATCH(10) + CRED(1) + SENDER(0) + NO_AUTH(1) = 12
    assert r.score == 12


def test_combined_spoof_critical() -> None:
    # Brand display spoof (HIGH=10) + DMARC fail (HIGH=10) = 20 -> CRITICAL.
    findings = [
        Finding(
            id="IDENT.DISPLAY_BRAND_SPOOF",
            title="t",
            severity=Severity.HIGH,
            reason="r",
        ),
    ]
    a = AuthResult(
        spf="fail", dkim="fail", dmarc="fail",
        spf_domain=None, dkim_domain=None, aligned=False,
    )
    findings += auth_to_findings(a)
    r = build_report("combined", "offline", findings, a, generated_at=GEN)
    assert r.category == RiskCategory.CRITICAL
    assert r.score >= 20


# --- ordering --------------------------------------------------------------


def test_stable_total_order() -> None:
    findings = [
        Finding(id="B", title="t", severity=Severity.LOW, reason="r"),
        Finding(id="A", title="t", severity=Severity.HIGH, reason="r"),
        Finding(id="C", title="t", severity=Severity.HIGH, reason="r", evidence="z"),
        Finding(id="C", title="t", severity=Severity.HIGH, reason="r", evidence="a"),
    ]
    ordered = sort_findings(findings)
    assert [(f.id, f.evidence) for f in ordered] == [
        ("A", None),
        ("C", "a"),
        ("C", "z"),
        ("B", None),
    ]


def test_shuffle_input_identical_report() -> None:
    base = [
        Finding(id="A", title="t", severity=Severity.HIGH, reason="r"),
        Finding(id="B", title="t", severity=Severity.LOW, reason="r"),
        Finding(id="C", title="t", severity=Severity.MEDIUM, reason="r"),
    ]
    r1 = build_report("t", "offline", list(base), None, generated_at=GEN)
    r2 = build_report("t", "offline", list(reversed(base)), None, generated_at=GEN)
    assert [f.id for f in r1.findings] == [f.id for f in r2.findings]
    assert render_json(r1) == render_json(r2)


# --- renderers -------------------------------------------------------------


def _sample_report():
    findings, a = _full_findings("link_mismatch.eml")
    return build_report("link_mismatch.eml", "offline", findings, a, generated_at=GEN)


def test_render_json_deterministic_and_roundtrips() -> None:
    r = _sample_report()
    a, b = render_json(r), render_json(r)
    assert a == b
    parsed = json.loads(a)
    assert parsed["category"] == r.category.value
    assert parsed["score"] == r.score
    assert {f["id"] for f in parsed["findings"]} == {f.id for f in r.findings}


def test_render_markdown_deterministic_shows_everything() -> None:
    r = _sample_report()
    a, b = render_markdown(r), render_markdown(r)
    assert a == b
    assert r.category.value in a
    assert f"Score:** {r.score}" in a
    for f in r.findings:
        assert f.id in a


def test_render_markdown_no_findings() -> None:
    r = build_report("clean", "offline", [], None, generated_at=GEN)
    md = render_markdown(r)
    assert "No findings." in md


def test_build_report_uses_injected_generated_at() -> None:
    r = build_report("t", "offline", [], None, generated_at="FIXED-TS")
    assert r.generated_at == "FIXED-TS"


def test_synthetic_parsed_does_not_break_builder() -> None:
    parsed = ParsedEmail(
        headers=HeaderSet(raw={}),
        from_display=None,
        from_addr="a@example.com",
        reply_to=None,
        return_path=None,
        subject=None,
        text_body=None,
        html_body=None,
        links=[Link(href="https://example.com/", anchor_text=None, source="text")],
        attachments=[],
    )
    finds = run_identity_link(parsed)
    r = build_report("syn", "offline", finds, None, generated_at=GEN)
    assert isinstance(r.score, int)
