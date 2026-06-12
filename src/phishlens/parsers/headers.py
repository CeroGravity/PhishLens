"""Header extraction helpers. Pure stdlib email. No interpretation."""

from __future__ import annotations

from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr

from phishlens.models import HeaderSet


def build_header_set(msg: Message) -> HeaderSet:
    """Collect all header occurrences, keys lowercased, values preserved.

    Multi-occurrence headers keep every value in order.
    """
    raw: dict[str, list[str]] = {}
    for key, value in msg.items():
        raw.setdefault(key.lower(), []).append(str(value))
    return HeaderSet(raw=raw)


def decode_rfc2047(value: str | None) -> str | None:
    """Decode RFC 2047 encoded-words to a unicode string, or None."""
    if value is None:
        return None
    return str(make_header(decode_header(value)))


def _first(msg: Message, name: str) -> str | None:
    """First raw value for a header, or None."""
    value = msg.get(name)
    return None if value is None else str(value)


def from_identity(msg: Message) -> tuple[str | None, str | None]:
    """Return (from_display, from_addr) for the first From header.

    Display name is RFC 2047 decoded. Empty strings become None.
    """
    raw = _first(msg, "From")
    if raw is None:
        return None, None
    display, addr = parseaddr(raw)
    display_decoded = decode_rfc2047(display) if display else None
    return (display_decoded or None), (addr or None)


def reply_to(msg: Message) -> str | None:
    """Addr-spec of Reply-To, or None."""
    raw = _first(msg, "Reply-To")
    if raw is None:
        return None
    _, addr = parseaddr(raw)
    return addr or None


def return_path(msg: Message) -> str | None:
    """Addr-spec of Return-Path with angle brackets stripped, or None."""
    raw = _first(msg, "Return-Path")
    if raw is None:
        return None
    _, addr = parseaddr(raw)
    if addr:
        return addr
    stripped = raw.strip().strip("<>").strip()
    return stripped or None


def subject(msg: Message) -> str | None:
    """RFC 2047 decoded Subject, or None."""
    return decode_rfc2047(_first(msg, "Subject"))
