"""Domain-age detector. Online-only, injectable RDAP client, injected `now`.

Offline (online=False or no client) -> [] with zero client calls. Deterministic:
the reference date `now` is always injected, never read from the clock.
"""

from __future__ import annotations

from datetime import date

from phishlens.models import Finding, ParsedEmail, Severity
from phishlens.util.domains import registrable_domain

from .rdap import RdapClient

_HIGH_DAYS = 30
_MEDIUM_DAYS = 90


def _target_domains(parsed: ParsedEmail) -> list[str]:
    """Registrable domains to check: sender + each link, dedup, stable order."""
    out: list[str] = []
    seen: set[str] = set()
    candidates: list[str] = []
    if parsed.from_addr:
        candidates.append(parsed.from_addr)
    candidates.extend(link.href for link in parsed.links)
    for raw in candidates:
        reg = registrable_domain(raw)
        if reg and reg not in seen:
            seen.add(reg)
            out.append(reg)
    return out


def find_newly_registered(
    parsed: ParsedEmail,
    *,
    online: bool = False,
    client: RdapClient | None = None,
    now: date,
) -> list[Finding]:
    if not online or client is None:
        return []

    findings: list[Finding] = []
    cache: dict[str, date | None] = {}

    for domain in _target_domains(parsed):
        if domain not in cache:
            cache[domain] = client.creation_date(domain)
        creation = cache[domain]
        if creation is None:
            continue  # unknown -> degrade gracefully, no finding
        age_days = (now - creation).days
        if age_days < _HIGH_DAYS:
            severity = Severity.HIGH
        elif age_days < _MEDIUM_DAYS:
            severity = Severity.MEDIUM
        else:
            continue
        findings.append(
            Finding(
                id="DOMAIN.NEWLY_REGISTERED",
                title="Domain was registered recently",
                severity=severity,
                reason=(
                    "The domain was registered recently; newly registered "
                    "domains are common in phishing."
                ),
                evidence=(
                    f"domain={domain} created={creation.isoformat()} "
                    f"now={now.isoformat()} age_days={age_days}"
                ),
            )
        )
    return findings
