"""Phase 5 DKIM crypto verify tests. Fully offline: keys generated in-test
via openssl, public key served through an injected dnsfunc (no real DNS)."""

from __future__ import annotations

import base64
import subprocess

import pytest

from phishlens.auth.dkim_verify import verify_dkim
from phishlens.models import Severity

_MSG = (
    b"From: alice@example.test\r\n"
    b"To: bob@example.test\r\n"
    b"Subject: hello\r\n"
    b"\r\n"
    b"This is the body.\r\n"
)


def _gen_keypair(tmp_path) -> tuple[bytes, str]:
    """Return (private_pem, public_key_b64_DER) using the system openssl."""
    priv = tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "genrsa", "-out", str(priv), "1024"],
        check=True,
        capture_output=True,
    )
    pub_der = subprocess.run(
        ["openssl", "rsa", "-in", str(priv), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    return priv.read_bytes(), base64.b64encode(pub_der).decode()


def _sign(priv_pem: bytes) -> bytes:
    import dkim

    sig = dkim.sign(
        _MSG,
        b"sel",
        b"example.test",
        priv_pem,
        include_headers=[b"from", b"to", b"subject"],
    )
    return sig + _MSG


def _dnsfunc_for(pub_b64: str):
    txt = ("v=DKIM1; k=rsa; p=" + pub_b64).encode()

    def dnsfunc(name, **kwargs):  # dkimpy passes name + kwargs
        return txt

    return dnsfunc


def test_valid_signature_no_finding(tmp_path) -> None:
    priv, pub = _gen_keypair(tmp_path)
    signed = _sign(priv)
    findings = verify_dkim(signed, online=True, dnsfunc=_dnsfunc_for(pub))
    assert findings == []


def test_tampered_body_fails(tmp_path) -> None:
    priv, pub = _gen_keypair(tmp_path)
    signed = _sign(priv)
    tampered = signed.replace(b"This is the body.", b"This is EVIL.")
    findings = verify_dkim(tampered, online=True, dnsfunc=_dnsfunc_for(pub))
    assert [f.id for f in findings] == ["AUTH.DKIM_VERIFY_FAIL"]
    assert findings[0].severity == Severity.HIGH
    assert "d=example.test" in (findings[0].evidence or "")


def test_offline_skips_and_never_calls_dnsfunc(tmp_path) -> None:
    priv, pub = _gen_keypair(tmp_path)
    signed = _sign(priv)
    called = {"n": 0}

    def counting_dnsfunc(name, **kwargs):
        called["n"] += 1
        return ("v=DKIM1; k=rsa; p=" + pub).encode()

    assert verify_dkim(signed, online=False, dnsfunc=counting_dnsfunc) == []
    assert called["n"] == 0


def test_no_signature_no_finding() -> None:
    assert verify_dkim(_MSG, online=True, dnsfunc=_dnsfunc_for("x")) == []


def test_malformed_no_crash_no_finding() -> None:
    # Has a DKIM-Signature header but it is garbage -> undetermined -> [].
    raw = b"DKIM-Signature: this is not a valid signature\r\n\r\nbody\r\n"

    def bad_dnsfunc(name, **kwargs):
        return b""

    findings = verify_dkim(raw, online=True, dnsfunc=bad_dnsfunc)
    assert findings == []


def test_openssl_available() -> None:
    # Guard: these tests require the system openssl for key generation.
    try:
        subprocess.run(["openssl", "version"], check=True, capture_output=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("openssl not available")
