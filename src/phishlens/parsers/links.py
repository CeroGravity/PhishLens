"""Link extraction from html and text bodies. Strings only.

Never fetches, resolves, normalizes via network, or expands shorteners.
Original href is preserved verbatim (Phase 3 needs the raw form).
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from phishlens.models import Link

# Bare/scheme URLs in plain text. Matches http(s):// URLs and bare www./
# domain-style hosts. Trailing punctuation is trimmed below.
_TEXT_URL_RE = re.compile(
    r"""(?xi)
    \b
    (
        https?://[^\s<>"']+
        |
        www\.[^\s<>"']+
    )
    """
)

# Trailing punctuation unlikely to belong to a URL.
_TRAILING = ".,;:!?)]}>\"'"


class _AnchorParser(HTMLParser):
    """Collects <a href=...> links with their inner text, in document order."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href_stack: list[str] = []
        self._text_stack: list[list[str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = None
        for name, value in attrs:
            if name.lower() == "href":
                href = value
                break
        if href is None:
            return
        self._href_stack.append(href)
        self._text_stack.append([])

    def handle_data(self, data: str) -> None:
        if self._text_stack:
            self._text_stack[-1].append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or not self._href_stack:
            return
        href = self._href_stack.pop()
        text = "".join(self._text_stack.pop()).strip()
        self.links.append(
            Link(href=href, anchor_text=text or None, source="html")
        )


def links_from_html(html_body: str | None) -> list[Link]:
    if not html_body:
        return []
    parser = _AnchorParser()
    parser.feed(html_body)
    parser.close()
    return parser.links


def links_from_text(text_body: str | None) -> list[Link]:
    if not text_body:
        return []
    links: list[Link] = []
    for match in _TEXT_URL_RE.finditer(text_body):
        href = match.group(1).rstrip(_TRAILING)
        if href:
            links.append(Link(href=href, anchor_text=None, source="text"))
    return links


def extract_links(text_body: str | None, html_body: str | None) -> list[Link]:
    """HTML links in document order, then text links in match order.

    Duplicates are kept.
    """
    return links_from_html(html_body) + links_from_text(text_body)
