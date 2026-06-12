"""Optional DKIM cryptographic verification (stretch).

Online-only and read-only over the raw message bytes. Offline default skips
verification entirely — the receiver's stamped Authentication-Results verdict
from Phase 2 stands. The signer's public key is fetched via an injectable
`dnsfunc` so tests run fully offline. Never modifies the message.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from phishlens.models import Finding, Severity

# dkimpy's dnsfunc takes a name (str) and returns the TXT record bytes/str.
DnsFunc = Callable[[str], object]

_SIG_HEADER_RE = re.compile(rb"^DKIM-Signature\s*:", re.IGNORECASE | re.MULTILINE)
_D_TAG = re.compile(rb"\bd\s*=\s*([^;\s]+)", re.IGNORECASE)
_S_TAG = re.compile(rb"\bs\s*=\s*([^;\s]+)", re.IGNORECASE)


def _has_dkim_signature(raw_bytes: bytes) -> bool:
    return _SIG_HEADER_RE.search(raw_bytes) is not None


def _signing_identity(raw_bytes: bytes) -> str:
    d = _D_TAG.search(raw_bytes)
    s = _S_TAG.search(raw_bytes)
    domain = d.group(1).decode("ascii", "replace") if d else "?"
    selector = s.group(1).decode("ascii", "replace") if s else "?"
    return f"selector={selector} d={domain}"


def verify_dkim(
    raw_bytes: bytes,
    *,
    online: bool = False,
    dnsfunc: DnsFunc | None = None,
) -> list[Finding]:
    if not online:
        return []
    if not _has_dkim_signature(raw_bytes):
        return []

    import dkim

    try:
        verifier = dkim.DKIM(raw_bytes)
        if dnsfunc is not None:
            valid = verifier.verify(dnsfunc=dnsfunc)
        else:
            valid = verifier.verify()
    except dkim.ValidationError:
        # A signature was present and failed validation (e.g. body/hash
        # mismatch). This is a definite verification failure.
        valid = False
    except Exception:
        # Malformed / unparsable / key error -> undetermined. Never crash,
        # never fabricate a pass, and do not assert a fail we can't prove.
        return []

    if valid:
        return []  # a passing signature is not an anomaly

    return [
        Finding(
            id="AUTH.DKIM_VERIFY_FAIL",
            title="DKIM signature failed cryptographic verification",
            severity=Severity.HIGH,
            reason=(
                "A DKIM-Signature is present but failed cryptographic "
                "verification against the signer's published key."
            ),
            evidence=_signing_identity(raw_bytes),
        )
    ]
