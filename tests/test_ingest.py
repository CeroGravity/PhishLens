"""Phase 1 ingest/extraction tests. Extraction only — no findings asserted."""

from __future__ import annotations

from pathlib import Path

from phishlens.ingest.eml import load_eml
from phishlens.models import ParsedEmail

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> ParsedEmail:
    return load_eml(str(FIXTURES / name))


def test_benign_plain_extraction() -> None:
    p = _load("benign_plain.eml")
    assert p.from_display == "Alice"
    assert p.from_addr == "alice@example.com"
    assert p.reply_to is None
    assert p.links == []
    assert p.attachments == []
    assert p.text_body is not None and p.text_body.strip() != ""


def test_spoof_displayname_extraction() -> None:
    p = _load("spoof_displayname.eml")
    assert p.from_display == "Example Bank Support"
    assert p.from_addr == "random@gmail.example"
    # Reply-To is an off-domain address (different domain from From).
    assert p.reply_to == "support@secure-example-bank.test"

    assert len(p.links) == 1
    link = p.links[0]
    assert link.source == "html"
    # Both raw strings are stored verbatim; no comparison/judgment made here.
    assert link.href == "http://login.secure-example-bank.test/verify"
    assert link.anchor_text == "www.examplebank.test"


def test_spoof_no_finding_produced() -> None:
    """Phase 1 stores href + anchor_text but produces no Finding/comparison."""
    p = _load("spoof_displayname.eml")
    # ParsedEmail has no findings/score/category fields at all.
    assert not hasattr(p, "findings")
    assert not hasattr(p, "score")
    # href != anchor host, but the parser does not derive or flag that.
    link = p.links[0]
    assert link.href != link.anchor_text


def test_dangerous_attachment_extraction() -> None:
    p = _load("dangerous_attachment.eml")
    assert len(p.attachments) == 1
    att = p.attachments[0]
    assert att.filename == "invoice.pdf.exe"
    assert att.extensions == ("pdf", "exe")
    assert att.content_type == "application/octet-stream"
    # Stub body byte length (harmless ASCII placeholder).
    assert att.size == 64


def test_encoded_word_subject_decodes() -> None:
    p = _load("encoded_subject.eml")
    assert p.subject == "Résumé attached"
    assert "=?" not in (p.subject or "")
    # Display name encoded-word also decodes.
    assert p.from_display == "Café Team"
    assert "=?" not in (p.from_display or "")


def test_headerset_keys_lowercased_and_multivalue() -> None:
    p = _load("spoof_displayname.eml")
    assert "from" in p.headers.raw
    assert "reply-to" in p.headers.raw
    # All keys lowercased.
    assert all(k == k.lower() for k in p.headers.raw)
    # Values are lists preserving occurrences.
    assert isinstance(p.headers.raw["from"], list)


def test_determinism_identical_input() -> None:
    a = _load("spoof_displayname.eml")
    b = _load("spoof_displayname.eml")
    assert a == b
