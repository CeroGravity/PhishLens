"""Single entry point: raw .eml bytes -> populated ParsedEmail.

Pure stdlib email. Offline. Deterministic. Extraction only — no findings,
no scoring, no auth verdicts, no comparisons.
"""

from __future__ import annotations

import email.policy
from email.parser import BytesParser

from phishlens.models import ParsedEmail
from phishlens.parsers.attachments import extract_attachments
from phishlens.parsers.headers import (
    build_header_set,
    from_identity,
    reply_to,
    return_path,
    subject,
)
from phishlens.parsers.links import extract_links
from phishlens.parsers.mime import select_bodies


def load_eml(path: str) -> ParsedEmail:
    """Parse a .eml file at ``path`` into a fully populated ParsedEmail."""
    with open(path, "rb") as fh:
        msg = BytesParser(policy=email.policy.default).parse(fh)

    from_display, from_addr = from_identity(msg)
    text_body, html_body = select_bodies(msg)

    return ParsedEmail(
        headers=build_header_set(msg),
        from_display=from_display,
        from_addr=from_addr,
        reply_to=reply_to(msg),
        return_path=return_path(msg),
        subject=subject(msg),
        text_body=text_body,
        html_body=html_body,
        links=extract_links(text_body, html_body),
        attachments=extract_attachments(msg),
    )
