"""Phase 5/8 DKIM crypto verify tests. Fully offline: committed static test
keys, public key served via an injected dnsfunc. No openssl, no skip, no DNS."""

from __future__ import annotations

from pathlib import Path

from phishlens.auth.dkim_verify import verify_dkim
from phishlens.models import Severity

_DKIM_DIR = Path(__file__).parent / "fixtures" / "dkim"
_PRIV = (_DKIM_DIR / "test_private.pem").read_bytes()
_PUB_B64 = (_DKIM_DIR / "test_public_b64.txt").read_text().strip()

_MSG = (
    b"From: alice@example.test\r\n"
    b"To: bob@example.test\r\n"
    b"Subject: hello\r\n"
    b"\r\n"
    b"This is the body.\r\n"
)


def _sign() -> bytes:
    import dkim

    sig = dkim.sign(
        _MSG,
        b"sel",
        b"example.test",
        _PRIV,
        include_headers=[b"from", b"to", b"subject"],
    )
    return sig + _MSG


def _dnsfunc(name, **kwargs):  # dkimpy passes name + kwargs
    return ("v=DKIM1; k=rsa; p=" + _PUB_B64).encode()


def test_valid_signature_no_finding() -> None:
    assert verify_dkim(_sign(), online=True, dnsfunc=_dnsfunc) == []


def test_tampered_body_fails() -> None:
    tampered = _sign().replace(b"This is the body.", b"This is EVIL.")
    findings = verify_dkim(tampered, online=True, dnsfunc=_dnsfunc)
    assert [f.id for f in findings] == ["AUTH.DKIM_VERIFY_FAIL"]
    assert findings[0].severity == Severity.HIGH
    assert "d=example.test" in (findings[0].evidence or "")


def test_offline_skips_and_never_calls_dnsfunc() -> None:
    called = {"n": 0}

    def counting_dnsfunc(name, **kwargs):
        called["n"] += 1
        return ("v=DKIM1; k=rsa; p=" + _PUB_B64).encode()

    assert verify_dkim(_sign(), online=False, dnsfunc=counting_dnsfunc) == []
    assert called["n"] == 0


def test_no_signature_no_finding() -> None:
    assert verify_dkim(_MSG, online=True, dnsfunc=_dnsfunc) == []


def test_malformed_no_crash_no_finding() -> None:
    raw = b"DKIM-Signature: this is not a valid signature\r\n\r\nbody\r\n"

    def bad_dnsfunc(name, **kwargs):
        return b""

    assert verify_dkim(raw, online=True, dnsfunc=bad_dnsfunc) == []
