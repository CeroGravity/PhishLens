"""PhishLens auth: stamped-verdict + strict-alignment extraction (data only).

No Findings, no scoring. Network is opt-in and injectable.
"""

from __future__ import annotations

from phishlens.models import AuthResult, ParsedEmail

from .alignment import from_domain, strict_aligned
from .dns import DnsMetadata, Resolver, lookup_metadata
from .results import extract_stamped_auth

__all__ = ["DnsMetadata", "Resolver", "analyze", "lookup_metadata"]


def analyze(
    parsed: ParsedEmail,
    *,
    online: bool = False,
    resolver: Resolver | None = None,
) -> AuthResult:
    """Populate AuthResult from stamped headers + strict alignment.

    Offline by default and deterministic. When ``online`` and a ``resolver``
    are provided, supplementary DNS metadata is retrieved but does NOT change
    the stamped spf/dkim/dmarc verdicts or alignment (held for Phase 6).
    """
    stamped = extract_stamped_auth(parsed.headers.raw)

    from_dom = from_domain(parsed.from_addr)
    aligned = strict_aligned(from_dom, stamped.dkim_domain, stamped.spf_domain)

    # Supplementary, verdict-neutral metadata. Retrieved only on the online
    # path; the result is intentionally not folded into AuthResult (Phase 6).
    if online and resolver is not None:
        _ = lookup_metadata(from_dom, online=online, resolver=resolver)

    return AuthResult(
        spf=stamped.spf,
        dkim=stamped.dkim,
        dmarc=stamped.dmarc,
        spf_domain=stamped.spf_domain,
        dkim_domain=stamped.dkim_domain,
        aligned=aligned,
    )
