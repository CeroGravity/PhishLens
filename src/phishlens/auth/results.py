"""Parse stamped authentication headers into raw method results + domains.

Trusts the receiving MTA's verdicts. Does not re-run SPF or verify DKIM
crypto (Phase 4 stretch). Parsing only. Operates on the lowercased header
dict from HeaderSet.raw (all occurrences preserved, in order).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# A method result token, e.g. "pass", "fail", "softfail", "permerror".
_RESULT_TOKEN = r"[a-zA-Z]+"


@dataclass
class StampedAuth:
    """Raw values extracted from auth-related headers (pre-alignment)."""

    spf: str | None
    dkim: str | None
    dmarc: str | None
    spf_domain: str | None
    dkim_domain: str | None
    header_from: str | None


def _values(raw: dict[str, list[str]], name: str) -> list[str]:
    """All occurrences of a header (keys in raw are lowercased), in order."""
    return raw.get(name.lower(), [])


def _parse_method(ar: str, method: str) -> str | None:
    """Extract `<method>=<result>` result token from an AR header value."""
    m = re.search(rf"\b{method}\s*=\s*({_RESULT_TOKEN})", ar, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _parse_property(ar: str, prop: str) -> str | None:
    """Extract a property like `header.d=` or `header.from=`."""
    m = re.search(rf"\b{re.escape(prop)}\s*=\s*([^\s;]+)", ar, re.IGNORECASE)
    return m.group(1).strip().lower() if m else None


def parse_authentication_results(
    raw: dict[str, list[str]],
) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """Return (spf, dkim, dmarc, dkim_header_d, header_from).

    Multiple Authentication-Results headers may exist; the topmost (first in
    header order, closest to delivery) is preferred. We take the first header
    that yields a value for each method/property.
    """
    spf = dkim = dmarc = dkim_d = header_from = None
    for value in _values(raw, "Authentication-Results"):
        if spf is None:
            spf = _parse_method(value, "spf")
        if dkim is None:
            dkim = _parse_method(value, "dkim")
        if dmarc is None:
            dmarc = _parse_method(value, "dmarc")
        if dkim_d is None:
            dkim_d = _parse_property(value, "header.d")
        if header_from is None:
            header_from = _parse_property(value, "header.from")
    return spf, dkim, dmarc, dkim_d, header_from


def _domain_of(addr: str | None) -> str | None:
    if not addr:
        return None
    if "@" in addr:
        return addr.rsplit("@", 1)[1].strip().lower() or None
    return addr.strip().lower() or None


def parse_received_spf(
    raw: dict[str, list[str]],
) -> tuple[str | None, str | None]:
    """Return (spf_result, spf_domain) from the topmost Received-SPF header."""
    values = _values(raw, "Received-SPF")
    if not values:
        return None, None
    top = values[0]
    result_match = re.match(rf"\s*({_RESULT_TOKEN})", top)
    spf_result = result_match.group(1).lower() if result_match else None
    env = _parse_property(top, "envelope-from")
    spf_domain = _domain_of(env)
    return spf_result, spf_domain


def parse_dkim_signature_domains(raw: dict[str, list[str]]) -> list[str]:
    """Signing domains from each DKIM-Signature `d=` tag, in header order."""
    domains: list[str] = []
    for value in _values(raw, "DKIM-Signature"):
        m = re.search(r"\bd\s*=\s*([^\s;]+)", value, re.IGNORECASE)
        if m:
            domains.append(m.group(1).strip().lower())
    return domains


def extract_stamped_auth(raw: dict[str, list[str]]) -> StampedAuth:
    spf, dkim, dmarc, dkim_d, header_from = parse_authentication_results(raw)

    spf_result, spf_domain = parse_received_spf(raw)
    # Prefer Authentication-Results for the spf field; use Received-SPF only
    # to fill the spf field when AR did not stamp one.
    if spf is None:
        spf = spf_result

    sig_domains = parse_dkim_signature_domains(raw)
    # dkim_domain: passing dkim with header.d wins; else first signature d=
    # (§2.1.3). header.d from a non-passing AR is not promoted.
    if dkim == "pass" and dkim_d:
        dkim_domain: str | None = dkim_d
    elif sig_domains:
        dkim_domain = sig_domains[0]
    else:
        dkim_domain = None

    return StampedAuth(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        spf_domain=spf_domain,
        dkim_domain=dkim_domain,
        header_from=header_from,
    )
