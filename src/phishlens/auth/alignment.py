"""Strict alignment only. No relaxed/org-domain (PSL) logic — deferred P4."""

from __future__ import annotations


def from_domain(from_addr: str | None) -> str | None:
    """Lowercased domain part of the From addr-spec, or None."""
    if not from_addr or "@" not in from_addr:
        return None
    return from_addr.rsplit("@", 1)[1].strip().lower() or None


def strict_aligned(
    from_dom: str | None,
    dkim_domain: str | None,
    spf_domain: str | None,
) -> bool | None:
    """Strict alignment: From domain exactly equals dkim_domain or spf_domain.

    Returns:
      None  if from_dom is unknown, or neither dkim_domain nor spf_domain known.
      True  if From domain exactly equals either known signing/envelope domain.
      False if at least one of them is known but neither matches.
    """
    if from_dom is None:
        return None
    if dkim_domain is None and spf_domain is None:
        return None
    if dkim_domain is not None and from_dom == dkim_domain:
        return True
    if spf_domain is not None and from_dom == spf_domain:
        return True
    return False
