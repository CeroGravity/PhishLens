"""DMARC-style relaxed alignment (registrable-domain based).

Phase 4 upgrade: alignment is now RELAXED (the DMARC default) — From's
registrable domain need only match the registrable domain of the DKIM signing
domain or the SPF envelope domain. Relaxed subsumes strict. The None rules
(insufficient data) are unchanged. models.py is not widened: aligned remains
bool | None; only its computation refines.
"""

from __future__ import annotations

from phishlens.util.domains import registrable_domain


def from_domain(from_addr: str | None) -> str | None:
    """Lowercased domain part of the From addr-spec, or None."""
    if not from_addr or "@" not in from_addr:
        return None
    return from_addr.rsplit("@", 1)[1].strip().lower() or None


def compute_relaxed_alignment(
    from_dom: str | None,
    dkim_domain: str | None,
    spf_domain: str | None,
) -> bool | None:
    """DMARC relaxed (registrable-domain) alignment.

    Returns:
      None  if from_dom is unknown, or neither dkim_domain nor spf_domain known.
      True  if From's registrable domain equals the registrable domain of
            either the DKIM signing domain or the SPF envelope domain.
      False if at least one is known but neither registrable domain matches.
    """
    if from_dom is None:
        return None
    if dkim_domain is None and spf_domain is None:
        return None

    from_reg = registrable_domain(from_dom)
    dkim_reg = registrable_domain(dkim_domain) if dkim_domain else None
    spf_reg = registrable_domain(spf_domain) if spf_domain else None

    if from_reg is None:
        return None
    if dkim_reg is not None and from_reg == dkim_reg:
        return True
    if spf_reg is not None and from_reg == spf_reg:
        return True
    return False
