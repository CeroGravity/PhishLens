"""Phase 3 detector tests. Exact finding-id sets + severities. No scoring."""

from __future__ import annotations

import sys
from pathlib import Path

from phishlens.heuristics import run_identity_link
from phishlens.ingest.eml import load_eml
from phishlens.models import Finding, Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _ids(name: str) -> set[str]:
    p = load_eml(str(FIXTURES / name))
    return {f.id for f in run_identity_link(p)}


def _findings(name: str) -> list[Finding]:
    return run_identity_link(load_eml(str(FIXTURES / name)))


def _sev(name: str) -> dict[str, Severity]:
    return {f.id: f.severity for f in _findings(name)}


def test_ident_replyto() -> None:
    assert _ids("ident_replyto.eml") == {"IDENT.REPLYTO_OFFDOMAIN"}
    assert _sev("ident_replyto.eml")["IDENT.REPLYTO_OFFDOMAIN"] == Severity.MEDIUM


def test_link_mismatch() -> None:
    assert _ids("link_mismatch.eml") == {
        "LINK.HREF_TEXT_MISMATCH",
        "LINK.CRED_KEYWORD",
        "LINK.SENDER_DOMAIN_MISMATCH",
    }
    sev = _sev("link_mismatch.eml")
    assert sev["LINK.HREF_TEXT_MISMATCH"] == Severity.HIGH
    assert sev["LINK.CRED_KEYWORD"] == Severity.LOW
    assert sev["LINK.SENDER_DOMAIN_MISMATCH"] == Severity.INFO


def test_link_ip() -> None:
    assert _ids("link_ip.eml") == {"LINK.RAW_IP", "LINK.CRED_KEYWORD"}
    sev = _sev("link_ip.eml")
    assert sev["LINK.RAW_IP"] == Severity.MEDIUM
    assert sev["LINK.CRED_KEYWORD"] == Severity.LOW


def test_link_punycode() -> None:
    assert _ids("link_punycode.eml") == {"LINK.PUNYCODE_IDN"}
    assert _sev("link_punycode.eml")["LINK.PUNYCODE_IDN"] == Severity.HIGH


def test_link_shortener() -> None:
    assert _ids("link_shortener.eml") == {"LINK.SHORTENER"}
    assert _sev("link_shortener.eml")["LINK.SHORTENER"] == Severity.LOW


def test_clean_control_zero_findings() -> None:
    assert run_identity_link(load_eml(str(FIXTURES / "auth_pass.eml"))) == []
    assert run_identity_link(load_eml(str(FIXTURES / "benign_plain.eml"))) == []


def test_subdomain_uses_registrable_domain() -> None:
    # From mail.example.com linking to www.example.com -> same registrable
    # domain -> no SENDER_DOMAIN_MISMATCH (proves registrable, not host).
    assert "LINK.SENDER_DOMAIN_MISMATCH" not in _ids("link_subdomain.eml")
    assert _ids("link_subdomain.eml") == set()


def test_tldextract_configured_offline() -> None:
    from phishlens.util import domains

    extractor = domains._EXTRACT
    # Live suffix-list fetch disabled (no URLs) => zero network calls.
    assert extractor.suffix_list_urls == ()
    # Reserved TLDs registered so synthetic .test fixtures resolve.
    assert "test" in extractor.extra_suffixes


def test_no_network_modules_imported() -> None:
    # The offline detector path must not pull in httpx / dnspython at import or
    # run time. Checked in a clean subprocess so other tests' imports (e.g. the
    # online DKIM tests, which legitimately import dkim/dns) don't pollute
    # sys.modules.
    import subprocess

    code = (
        "import sys;"
        "from phishlens.heuristics import run_identity_link;"
        "from phishlens.ingest.eml import load_eml;"
        f"run_identity_link(load_eml({str(FIXTURES / 'link_mismatch.eml')!r}));"
        "assert 'httpx' not in sys.modules, 'httpx imported';"
        "assert 'dns' not in sys.modules, 'dns imported'"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True)
    assert result.returncode == 0, result.stderr.decode()


def test_determinism_order_included() -> None:
    p = load_eml(str(FIXTURES / "link_mismatch.eml"))
    a = run_identity_link(p)
    b = run_identity_link(p)
    assert a == b
    assert [f.id for f in a] == [f.id for f in b]


def test_collector_returns_only_findings_no_score() -> None:
    findings = run_identity_link(load_eml(str(FIXTURES / "link_mismatch.eml")))
    assert isinstance(findings, list)
    assert all(isinstance(f, Finding) for f in findings)
    # No aggregation surfaced.
    assert not hasattr(findings, "score")
    assert not hasattr(findings, "category")


def test_multiple_from_and_missing_message_id() -> None:
    # Build a ParsedEmail directly to exercise header anomalies deterministically.
    from phishlens.models import HeaderSet, ParsedEmail

    parsed = ParsedEmail(
        headers=HeaderSet(
            raw={"from": ["a@example.com", "b@example.com"]}
        ),
        from_display=None,
        from_addr="a@example.com",
        reply_to=None,
        return_path=None,
        subject=None,
        text_body=None,
        html_body=None,
        links=[],
        attachments=[],
    )
    ids = {f.id for f in run_identity_link(parsed)}
    assert "HDR.MULTIPLE_FROM" in ids
    assert "HDR.MISSING_MESSAGE_ID" in ids
