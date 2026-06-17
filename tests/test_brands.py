"""Phase 4 brand-detector + typosquat-util + relaxed-alignment tests."""

from __future__ import annotations

from pathlib import Path

from phishlens import auth
from phishlens.data.brands import Brand, load_brands
from phishlens.heuristics import run_brand
from phishlens.ingest.eml import load_eml
from phishlens.models import HeaderSet, ParsedEmail, Severity
from phishlens.util import typosquat
from phishlens.util.typosquat import (
    homoglyph_normalize,
    is_combosquat,
    is_typosquat,
    levenshtein,
)

FIXTURES = Path(__file__).parent / "fixtures"

# Synthetic brand map keeps lookalikes in reserved space (CLAUDE.md §5).
SYNTH_BRANDS = (
    Brand("examplebank", ("example bank", "examplebank"), ("examplebank.test",)),
)


def _brand_ids(name: str) -> set[str]:
    p = load_eml(str(FIXTURES / name))
    return {f.id for f in run_brand(p, brands=SYNTH_BRANDS)}


def _brand_sev(name: str) -> dict[str, Severity]:
    p = load_eml(str(FIXTURES / name))
    return {f.id: f.severity for f in run_brand(p, brands=SYNTH_BRANDS)}


# --- fixture exact sets ----------------------------------------------------


def test_brand_typosquat() -> None:
    assert _brand_ids("brand_typosquat.eml") == {"LINK.TYPOSQUAT"}
    assert _brand_sev("brand_typosquat.eml")["LINK.TYPOSQUAT"] == Severity.HIGH


def test_brand_tldswap() -> None:
    assert _brand_ids("brand_tldswap.eml") == {"LINK.TLD_SWAP"}
    assert _brand_sev("brand_tldswap.eml")["LINK.TLD_SWAP"] == Severity.HIGH


def test_brand_combosquat() -> None:
    assert _brand_ids("brand_combosquat.eml") == {"LINK.COMBOSQUAT"}
    assert _brand_sev("brand_combosquat.eml")["LINK.COMBOSQUAT"] == Severity.MEDIUM


def test_brand_display_spoof() -> None:
    assert _brand_ids("brand_display_spoof.eml") == {"IDENT.DISPLAY_BRAND_SPOOF"}
    assert (
        _brand_sev("brand_display_spoof.eml")["IDENT.DISPLAY_BRAND_SPOOF"]
        == Severity.HIGH
    )


def test_brand_clean_control() -> None:
    p = load_eml(str(FIXTURES / "auth_pass.eml"))
    assert run_brand(p, brands=SYNTH_BRANDS) == []


# --- typosquat unit --------------------------------------------------------


def test_levenshtein_values() -> None:
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("paypal", "paypall") == 1
    assert levenshtein("abc", "xyz") == 3


def test_homoglyph_normalize() -> None:
    assert homoglyph_normalize("paypa1") == "paypal"
    assert homoglyph_normalize("g00gle") == "google"
    assert homoglyph_normalize("rnicrosoft") == "microsoft"


def test_exact_legit_domain_not_flagged() -> None:
    # examplebank.test is the legit synthetic domain -> no brand finding.
    parsed = _synthetic(from_addr="user@examplebank.test", links=[])
    assert run_brand(parsed, brands=SYNTH_BRANDS) == []


def test_short_sld_guard() -> None:
    # 3-char SLDs are below MIN_SLD_LEN; no edit-distance-1 false positives.
    assert is_typosquat("ups", "usp") is False
    assert typosquat.MIN_SLD_LEN == 4
    assert is_combosquat("xupsx", "ups") is False  # token too short to combo


def test_shipped_brand_list_flags_paypal_lookalike() -> None:
    # Pure unit: shipped load_brands() flags paypa1 (homoglyph of paypal).
    parsed = _synthetic(
        from_addr="noreply@example.com",
        links=["https://paypa1.com/login"],
    )
    ids = {f.id for f in run_brand(parsed, brands=load_brands())}
    assert "LINK.TYPOSQUAT" in ids


# --- relaxed alignment retrofit -------------------------------------------


def test_relaxed_alignment_phase2_fixtures_unchanged() -> None:
    assert auth.analyze(load_eml(str(FIXTURES / "auth_pass.eml"))).aligned is True
    assert (
        auth.analyze(load_eml(str(FIXTURES / "auth_misaligned.eml"))).aligned
        is False
    )
    assert auth.analyze(load_eml(str(FIXTURES / "auth_fail.eml"))).aligned is None
    assert auth.analyze(load_eml(str(FIXTURES / "no_auth.eml"))).aligned is None


def test_auth_subdomain_relaxed_true() -> None:
    # From @mail.example.com, DKIM d=example.com -> strict False, relaxed True.
    assert (
        auth.analyze(load_eml(str(FIXTURES / "auth_subdomain.eml"))).aligned
        is True
    )


# --- determinism & boundary ------------------------------------------------


def test_brand_determinism_order_included() -> None:
    p = load_eml(str(FIXTURES / "brand_combosquat.eml"))
    a = run_brand(p, brands=SYNTH_BRANDS)
    b = run_brand(p, brands=SYNTH_BRANDS)
    assert a == b
    assert [f.id for f in a] == [f.id for f in b]


def test_brand_findings_only_no_score() -> None:
    findings = run_brand(
        load_eml(str(FIXTURES / "brand_typosquat.eml")), brands=SYNTH_BRANDS
    )
    assert all(hasattr(f, "severity") for f in findings)
    assert not hasattr(findings, "score")
    assert not hasattr(findings, "category")


# --- helpers ---------------------------------------------------------------


def test_claude_md_parity() -> None:
    import pytest

    root = Path(__file__).resolve().parents[1] / "CLAUDE.md"
    dotclaude = Path(__file__).resolve().parents[1] / ".claude" / "CLAUDE.md"
    if not root.exists():
        pytest.skip("root CLAUDE.md intentionally absent; governance lives in .claude/")
    assert root.read_bytes() == dotclaude.read_bytes()


def _synthetic(*, from_addr: str, links: list[str]) -> ParsedEmail:
    from phishlens.models import Link

    return ParsedEmail(
        headers=HeaderSet(raw={"from": [from_addr]}),
        from_display=None,
        from_addr=from_addr,
        reply_to=None,
        return_path=None,
        subject=None,
        text_body=None,
        html_body=None,
        links=[Link(href=h, anchor_text=None, source="text") for h in links],
        attachments=[],
    )
