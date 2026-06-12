"""Phase 0 model-contract tests. No detection assertions."""

from __future__ import annotations

import dataclasses

import pytest

from phishlens.models import (
    Attachment,
    AuthResult,
    Finding,
    HeaderSet,
    Link,
    ParsedEmail,
    Report,
    RiskCategory,
    Severity,
)


def test_construct_each_dataclass() -> None:
    finding = Finding(
        id="X1",
        title="Example",
        severity=Severity.LOW,
        reason="because",
        evidence=None,
    )
    headers = HeaderSet(raw={"From": ["Alice <alice@example.com>"]})
    link = Link(href="http://example.test/", anchor_text="click", source="html")
    attachment = Attachment(
        filename="invoice.pdf.exe",
        content_type="application/octet-stream",
        size=42,
        extensions=("pdf", "exe"),
    )
    auth = AuthResult(
        spf="pass",
        dkim="pass",
        dmarc="pass",
        spf_domain="example.com",
        dkim_domain="example.com",
        aligned=True,
    )
    parsed = ParsedEmail(
        headers=headers,
        from_display="Alice",
        from_addr="alice@example.com",
        reply_to=None,
        return_path=None,
        subject="hi",
        text_body="body",
        html_body=None,
        links=[link],
        attachments=[attachment],
    )
    report = Report(
        target="message.eml",
        mode="offline",
        category=RiskCategory.LOW,
        score=0,
        findings=[finding],
        auth=auth,
        generated_at="2024-01-01T00:00:00Z",
    )

    assert parsed.links == [link]
    assert parsed.attachments == [attachment]
    assert report.findings == [finding]


def test_finding_is_frozen() -> None:
    finding = Finding(id="X1", title="t", severity=Severity.HIGH, reason="r")
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.id = "X2"  # type: ignore[misc]


def test_headerset_get_is_case_insensitive() -> None:
    headers = HeaderSet(raw={"From": ["Alice <alice@example.com>"], "X-Foo": ["bar"]})
    assert headers.get("from") == "Alice <alice@example.com>"
    assert headers.get("FROM") == "Alice <alice@example.com>"
    assert headers.get("x-foo") == "bar"
    assert headers.get("missing") is None


def test_report_to_dict_round_trips_keys() -> None:
    auth = AuthResult(
        spf="pass",
        dkim="pass",
        dmarc="pass",
        spf_domain="example.com",
        dkim_domain="example.com",
        aligned=True,
    )
    report = Report(
        target="message.eml",
        mode="offline",
        category=RiskCategory.MEDIUM,
        score=10,
        findings=[Finding(id="X1", title="t", severity=Severity.LOW, reason="r")],
        auth=auth,
        generated_at="2024-01-01T00:00:00Z",
    )
    d = report.to_dict()

    assert set(d.keys()) == {
        "target",
        "mode",
        "category",
        "score",
        "findings",
        "auth",
        "generated_at",
    }
    assert d["category"] == "MEDIUM"
    assert d["findings"][0]["severity"] == "LOW"
    assert set(d["auth"].keys()) == {
        "spf",
        "dkim",
        "dmarc",
        "spf_domain",
        "dkim_domain",
        "aligned",
    }


def test_report_to_dict_handles_no_auth() -> None:
    report = Report(
        target="http://example.test/",
        mode="offline",
        category=RiskCategory.LOW,
        score=0,
        findings=[],
        auth=None,
        generated_at="2024-01-01T00:00:00Z",
    )
    assert report.to_dict()["auth"] is None
