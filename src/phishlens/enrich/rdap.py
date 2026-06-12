"""RDAP client: domain registration date lookup.

RDAP queries a registry ABOUT a domain. It never touches the suspicious host
and never fetches a URL found in the message (CLAUDE.md §3/§4). Strictly
behind `--online`, injectable, offline default = no lookup.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Protocol


class RdapClient(Protocol):
    """Returns a domain's registration (creation) date, or None if unknown."""

    def creation_date(self, domain: str) -> date | None:  # pragma: no cover
        ...


def _parse_registration_date(payload: dict) -> date | None:
    """Extract the `registration` event date from an RDAP domain response."""
    events = payload.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") == "registration":
            raw = event.get("eventDate")
            if isinstance(raw, str):
                return _parse_iso_date(raw)
    return None


def _parse_iso_date(raw: str) -> date | None:
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            return None


class HttpxRdapClient:
    """Default sync RDAP client over httpx. Network path is exercised only in
    the operator's `--online` environment, never in tests."""

    def __init__(self, base_url: str = "https://rdap.org/domain/") -> None:
        self._base_url = base_url

    def creation_date(self, domain: str) -> date | None:
        import httpx

        url = f"{self._base_url}{domain}"
        try:
            resp = httpx.get(url, timeout=10.0, follow_redirects=True)
            resp.raise_for_status()
            payload = resp.json()
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        return _parse_registration_date(payload)
