"""Phase 2 auth tests. Data only — no Findings asserted/expected."""

from __future__ import annotations

from pathlib import Path

from phishlens import auth
from phishlens.auth.dns import DnsMetadata, lookup_metadata
from phishlens.ingest.eml import load_eml
from phishlens.models import AuthResult, ParsedEmail

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> ParsedEmail:
    return load_eml(str(FIXTURES / name))


def test_auth_pass() -> None:
    r = auth.analyze(_load("auth_pass.eml"))
    assert r == AuthResult(
        spf="pass",
        dkim="pass",
        dmarc="pass",
        spf_domain="example.com",
        dkim_domain="example.com",
        aligned=True,
    )


def test_auth_fail() -> None:
    r = auth.analyze(_load("auth_fail.eml"))
    # No Received-SPF and no DKIM-Signature -> no domains -> aligned is None.
    assert r == AuthResult(
        spf="fail",
        dkim="fail",
        dmarc="fail",
        spf_domain=None,
        dkim_domain=None,
        aligned=None,
    )


def test_auth_misaligned() -> None:
    r = auth.analyze(_load("auth_misaligned.eml"))
    assert r == AuthResult(
        spf=None,
        dkim="pass",
        dmarc="fail",
        spf_domain=None,
        dkim_domain="other.test",
        aligned=False,
    )


def test_no_auth() -> None:
    r = auth.analyze(_load("no_auth.eml"))
    assert r == AuthResult(
        spf=None,
        dkim=None,
        dmarc=None,
        spf_domain=None,
        dkim_domain=None,
        aligned=None,
    )


# --- DNS injection ---------------------------------------------------------


class _FakeResolver:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def txt(self, name: str) -> list[str]:
        self.calls.append(name)
        if name.startswith("_dmarc."):
            return ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        if name.startswith("sel1._domainkey."):
            return ["v=DKIM1; k=rsa; p=AAAA"]
        return ["v=spf1 include:example.com -all"]


def test_dns_online_retrieves_dmarc_policy() -> None:
    resolver = _FakeResolver()
    meta = lookup_metadata(
        "example.com", online=True, resolver=resolver, dkim_selector="sel1"
    )
    assert meta.dmarc_policy == "reject"
    assert meta.spf_present is True
    assert meta.dkim_selector_present is True
    assert "_dmarc.example.com" in resolver.calls


def test_dns_offline_zero_calls_and_unknown() -> None:
    resolver = _FakeResolver()
    # offline=True path via analyze: no resolver consultation at all.
    auth.analyze(_load("auth_pass.eml"), online=False, resolver=resolver)
    assert resolver.calls == []

    # Direct offline lookup returns all-unknown without touching resolver.
    meta = lookup_metadata("example.com", online=False, resolver=resolver)
    assert meta == DnsMetadata()
    assert resolver.calls == []


def test_dns_no_resolver_is_unknown() -> None:
    meta = lookup_metadata("example.com", online=True, resolver=None)
    assert meta == DnsMetadata()


# --- determinism & negatives ----------------------------------------------


def test_offline_determinism() -> None:
    p = _load("auth_misaligned.eml")
    assert auth.analyze(p) == auth.analyze(p)


def test_analyze_returns_authresult_not_finding() -> None:
    r = auth.analyze(_load("auth_pass.eml"))
    assert isinstance(r, AuthResult)
    # No findings/score surfaced by auth.
    assert not hasattr(r, "findings")
    assert not hasattr(r, "severity")


def test_auth_does_not_import_scoring_or_heuristics() -> None:
    # Importing the auth package must not pull in scoring/heuristics, and the
    # auth module namespaces must expose no Finding symbol.
    import sys

    import phishlens.auth as auth_pkg
    import phishlens.auth.alignment as alignment_mod
    import phishlens.auth.dns as dns_mod
    import phishlens.auth.results as results_mod

    assert "phishlens.scoring" not in sys.modules
    assert "phishlens.heuristics" not in sys.modules

    for mod in (auth_pkg, alignment_mod, dns_mod, results_mod):
        assert not hasattr(mod, "Finding")
