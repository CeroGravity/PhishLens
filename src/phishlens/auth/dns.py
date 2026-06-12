"""Injectable, offline-by-default DNS metadata retrieval.

No network unless ``online`` is True AND a resolver is supplied. The resolver
is a thin protocol so tests run fully offline. Retrieves record presence /
metadata only; never changes the receiver's stamped verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class Resolver(Protocol):
    """Minimal injectable resolver: name -> list of TXT strings."""

    def txt(self, name: str) -> list[str]:  # pragma: no cover - protocol
        ...


@dataclass
class DnsMetadata:
    """Supplementary domain metadata. Does not affect AuthResult verdicts."""

    dmarc_policy: str | None = None  # `p=` from _dmarc TXT
    spf_present: bool | None = None  # a v=spf1 TXT exists
    dkim_selector_present: bool | None = None


def _dmarc_policy(txts: list[str]) -> str | None:
    for txt in txts:
        if "v=DMARC1" in txt or "v=dmarc1" in txt.lower():
            for part in txt.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    return part.split("=", 1)[1].strip().lower() or None
    return None


def _spf_present(txts: list[str]) -> bool:
    return any(t.strip().lower().startswith("v=spf1") for t in txts)


def lookup_metadata(
    domain: str | None,
    *,
    online: bool,
    resolver: Resolver | None,
    dkim_selector: str | None = None,
) -> DnsMetadata:
    """Offline-deterministic. Returns all-unknown unless online + resolver."""
    if not online or resolver is None or not domain:
        return DnsMetadata()

    dmarc_txts = resolver.txt(f"_dmarc.{domain}")
    spf_txts = resolver.txt(domain)

    dkim_present: bool | None = None
    if dkim_selector:
        dkim_txts = resolver.txt(f"{dkim_selector}._domainkey.{domain}")
        dkim_present = len(dkim_txts) > 0

    return DnsMetadata(
        dmarc_policy=_dmarc_policy(dmarc_txts),
        spf_present=_spf_present(spf_txts),
        dkim_selector_present=dkim_present,
    )
