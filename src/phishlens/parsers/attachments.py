"""Attachment metadata extraction. Filename + MIME + size + extensions only.

Never decompresses, opens containers, inspects macros, writes to disk, or
invokes any interpreter (CLAUDE.md §3.4). Payload bytes are read into memory
solely to measure size.
"""

from __future__ import annotations

from email.message import Message

from phishlens.models import Attachment

from .headers import decode_rfc2047


def _is_attachment_part(part: Message) -> bool:
    if part.is_multipart():
        return False
    if part.get_content_disposition() == "attachment":
        return True
    return part.get_filename() is not None


def _split_extensions(filename: str | None) -> tuple[str, ...]:
    """Lowercase dot-split tail of the filename, excluding the base name.

    'invoice.pdf.exe' -> ('pdf', 'exe'); no dots -> ().
    """
    if not filename:
        return ()
    parts = filename.split(".")
    if len(parts) <= 1:
        return ()
    return tuple(p.lower() for p in parts[1:])


def _payload_size(part: Message) -> int:
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return len(payload)
    return 0


def extract_attachments(msg: Message) -> list[Attachment]:
    attachments: list[Attachment] = []
    for part in msg.walk():
        if not _is_attachment_part(part):
            continue
        filename = decode_rfc2047(part.get_filename())
        content_type = part.get_content_type().lower()
        attachments.append(
            Attachment(
                filename=filename,
                content_type=content_type,
                size=_payload_size(part),
                extensions=_split_extensions(filename),
            )
        )
    return attachments
