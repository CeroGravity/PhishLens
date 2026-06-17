"""Phase 7 scoring + auth-adapter unit tests."""

from __future__ import annotations

from phishlens.heuristics.auth_findings import auth_to_findings
from phishlens.models import AuthResult, Finding, RiskCategory, Severity
from phishlens.scoring import categorize, score
from phishlens.scoring.config import SEVERITY_WEIGHTS


def _f(sev: Severity, fid: str = "X") -> Finding:
    return Finding(id=fid, title="t", severity=sev, reason="r")


def test_weight_values() -> None:
    assert SEVERITY_WEIGHTS[Severity.INFO] == 0
    assert SEVERITY_WEIGHTS[Severity.LOW] == 1
    assert SEVERITY_WEIGHTS[Severity.MEDIUM] == 4
    assert SEVERITY_WEIGHTS[Severity.HIGH] == 10
    assert SEVERITY_WEIGHTS[Severity.CRITICAL] == 20


def test_score_sum_and_cap() -> None:
    assert score([]) == 0
    assert score([_f(Severity.HIGH), _f(Severity.MEDIUM)]) == 14
    # cap at 100 (11 HIGH = 110 -> 100)
    assert score([_f(Severity.HIGH) for _ in range(11)]) == 100


def test_category_boundaries() -> None:
    assert categorize(0) == RiskCategory.LOW
    assert categorize(3) == RiskCategory.LOW
    assert categorize(4) == RiskCategory.MEDIUM
    assert categorize(9) == RiskCategory.MEDIUM
    assert categorize(10) == RiskCategory.HIGH
    assert categorize(19) == RiskCategory.HIGH
    assert categorize(20) == RiskCategory.CRITICAL
    assert categorize(100) == RiskCategory.CRITICAL


# --- auth adapter ----------------------------------------------------------


def _auth(**kw) -> AuthResult:
    base = dict(
        spf=None, dkim=None, dmarc=None,
        spf_domain=None, dkim_domain=None, aligned=None,
    )
    base.update(kw)
    return AuthResult(**base)


def _map(auth: AuthResult) -> dict[str, Severity]:
    return {f.id: f.severity for f in auth_to_findings(auth)}


def test_adapter_dmarc_fail() -> None:
    assert _map(_auth(dmarc="fail"))["AUTH.DMARC_FAIL"] == Severity.HIGH


def test_adapter_spf_fail_and_softfail() -> None:
    assert _map(_auth(spf="fail"))["AUTH.SPF_FAIL"] == Severity.MEDIUM
    assert _map(_auth(spf="softfail"))["AUTH.SPF_FAIL"] == Severity.MEDIUM


def test_adapter_dkim_fail() -> None:
    assert _map(_auth(dkim="fail"))["AUTH.DKIM_FAIL"] == Severity.MEDIUM


def test_adapter_not_aligned() -> None:
    assert _map(_auth(aligned=False))["AUTH.NOT_ALIGNED"] == Severity.MEDIUM


def test_adapter_no_auth() -> None:
    m = _map(_auth())  # all None
    assert m == {"AUTH.NO_AUTH": Severity.LOW}


def test_adapter_pass_and_none_produce_nothing() -> None:
    # pass results / aligned True with at least one verdict present -> no finding
    assert auth_to_findings(_auth(spf="pass", dkim="pass", dmarc="pass",
                                  aligned=True)) == []


def test_adapter_none_input() -> None:
    assert auth_to_findings(None) == []


def test_adapter_does_not_emit_dkim_verify_fail() -> None:
    # AUTH.DKIM_VERIFY_FAIL belongs to the Phase-5 online path, not the adapter.
    for kw in ({"dkim": "fail"}, {"dmarc": "fail"}, {}):
        ids = {f.id for f in auth_to_findings(_auth(**kw))}
        assert "AUTH.DKIM_VERIFY_FAIL" not in ids
