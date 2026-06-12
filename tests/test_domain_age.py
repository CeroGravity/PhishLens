"""Phase 5 domain-age tests. Fully offline: RDAP client is a fake recorder."""

from __future__ import annotations

from datetime import date, timedelta

from phishlens.enrich.domain_age import find_newly_registered
from phishlens.heuristics import run_online_enrichment
from phishlens.models import HeaderSet, Link, ParsedEmail, Severity

NOW = date(2024, 6, 1)


class _FakeRdap:
    """Call-recording fake. Maps registrable domain -> creation date."""

    def __init__(self, mapping: dict[str, date | None]) -> None:
        self._mapping = mapping
        self.calls: list[str] = []

    def creation_date(self, domain: str) -> date | None:
        self.calls.append(domain)
        return self._mapping.get(domain)


def _parsed(from_addr: str | None, link_hosts: list[str]) -> ParsedEmail:
    return ParsedEmail(
        headers=HeaderSet(raw={}),
        from_display=None,
        from_addr=from_addr,
        reply_to=None,
        return_path=None,
        subject=None,
        text_body=None,
        html_body=None,
        links=[Link(href=h, anchor_text=None, source="text") for h in link_hosts],
        attachments=[],
    )


def test_severity_buckets() -> None:
    client = _FakeRdap(
        {
            "sender.test": NOW - timedelta(days=10),  # HIGH (<30)
            "link-a.test": NOW - timedelta(days=60),  # MEDIUM (<90)
            "old.test": NOW - timedelta(days=800),  # none
        }
    )
    parsed = _parsed(
        "user@sender.test",
        ["https://link-a.test/x", "https://old.test/y"],
    )
    findings = find_newly_registered(parsed, online=True, client=client, now=NOW)
    by_dom = {f.evidence.split()[0]: f for f in findings}  # type: ignore[union-attr]
    assert by_dom["domain=sender.test"].severity == Severity.HIGH
    assert by_dom["domain=link-a.test"].severity == Severity.MEDIUM
    # old.test produced no finding
    assert all("old.test" not in (f.evidence or "") for f in findings)
    assert {f.id for f in findings} == {"DOMAIN.NEWLY_REGISTERED"}


def test_offline_zero_calls() -> None:
    client = _FakeRdap({"sender.test": NOW - timedelta(days=1)})
    parsed = _parsed("user@sender.test", [])
    assert find_newly_registered(parsed, online=False, client=client, now=NOW) == []
    assert client.calls == []


def test_no_client_zero_findings() -> None:
    parsed = _parsed("user@sender.test", [])
    assert find_newly_registered(parsed, online=True, client=None, now=NOW) == []


def test_unknown_creation_date_no_finding() -> None:
    client = _FakeRdap({"sender.test": None})
    parsed = _parsed("user@sender.test", [])
    assert find_newly_registered(parsed, online=True, client=client, now=NOW) == []
    assert client.calls == ["sender.test"]  # queried, but None -> no finding


def test_dedup_cache_one_call_per_registrable_domain() -> None:
    client = _FakeRdap({"dup.test": NOW - timedelta(days=5)})
    # Two links under the same registrable domain + sender on it.
    parsed = _parsed(
        "user@dup.test",
        ["https://a.dup.test/1", "https://b.dup.test/2"],
    )
    findings = find_newly_registered(parsed, online=True, client=client, now=NOW)
    assert client.calls == ["dup.test"]  # queried exactly once
    assert len(findings) == 1


def test_determinism_injected_now() -> None:
    client_a = _FakeRdap({"sender.test": NOW - timedelta(days=10)})
    client_b = _FakeRdap({"sender.test": NOW - timedelta(days=10)})
    parsed = _parsed("user@sender.test", [])
    a = find_newly_registered(parsed, online=True, client=client_a, now=NOW)
    b = find_newly_registered(parsed, online=True, client=client_b, now=NOW)
    assert a == b


def test_collector_offline_returns_empty_no_calls() -> None:
    client = _FakeRdap({"sender.test": NOW - timedelta(days=1)})
    parsed = _parsed("user@sender.test", [])
    out = run_online_enrichment(
        parsed, online=False, rdap_client=client, now=NOW
    )
    assert out == []
    assert client.calls == []
