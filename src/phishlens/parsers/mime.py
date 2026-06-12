"""MIME body selection. Walks parts; extracts first text/plain and text/html.

Skips parts marked as attachments. Charset-aware decode. No network.
"""

from __future__ import annotations

from email.message import Message


def _is_attachment(part: Message) -> bool:
    disposition = part.get_content_disposition()
    return disposition == "attachment"


def _decode_text(part: Message) -> str | None:
    """Decode a leaf part's payload to text, charset-aware."""
    payload = part.get_payload(decode=True)
    if payload is None:
        return None
    if not isinstance(payload, bytes):
        return None
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, ValueError):
        return payload.decode("utf-8", errors="replace")


def select_bodies(msg: Message) -> tuple[str | None, str | None]:
    """Return (text_body, html_body): first non-attachment part of each type."""
    text_body: str | None = None
    html_body: str | None = None

    for part in msg.walk():
        if part.is_multipart():
            continue
        if _is_attachment(part):
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain" and text_body is None:
            text_body = _decode_text(part)
        elif content_type == "text/html" and html_body is None:
            html_body = _decode_text(part)

    return text_body, html_body
