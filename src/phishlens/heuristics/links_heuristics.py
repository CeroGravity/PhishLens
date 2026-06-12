"""Link-based detectors. STRINGS ONLY — never fetch, resolve, or expand any
href (CLAUDE.md §3.2/§3.3). Operates on parsed.links from Phase 1.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit

from phishlens.models import Finding, Link, ParsedEmail, Severity
from phishlens.util.domains import host_of, is_ip_literal, registrable_domain

# Embedded shortener set. Flag only — NEVER expand (CLAUDE.md §3.3).
_SHORTENERS = frozenset(
    {
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
    }
)

_CRED_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "account",
    "secure",
    "update",
    "confirm",
    "password",
    "webscr",
    "banking",
    "wallet",
)
_CRED_RE = re.compile(
    r"(?i)(?<![a-z])(" + "|".join(re.escape(k) for k in _CRED_KEYWORDS) + r")(?![a-z])"
)

# Anchor text that is itself URL/domain-like (so a mismatch is meaningful).
_ANCHOR_URLISH = re.compile(
    r"(?i)^\s*(?:https?://)?(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}(?:[/:?].*)?\s*$"
)


def _href_host(href: str) -> str | None:
    return host_of(href)


def _is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def _is_mixed_script(host: str) -> bool:
    """Best-effort: a single label mixing ASCII letters and non-ASCII letters."""
    for label in host.split("."):
        scripts = set()
        for ch in label:
            if not ch.isalpha():
                continue
            scripts.add("ascii" if ch.isascii() else _script_name(ch))
        if len(scripts) > 1:
            return True
    return False


def _script_name(ch: str) -> str:
    try:
        return unicodedata.name(ch).split(" ")[0]
    except ValueError:
        return "unknown"


def detect_href_text_mismatch(link: Link, _from_dom: str | None) -> list[Finding]:
    if link.anchor_text is None or not _ANCHOR_URLISH.match(link.anchor_text):
        return []
    anchor_dom = registrable_domain(link.anchor_text)
    href_dom = registrable_domain(link.href)
    if anchor_dom is None or href_dom is None or anchor_dom == href_dom:
        return []
    return [
        Finding(
            id="LINK.HREF_TEXT_MISMATCH",
            title="Link text domain differs from its href",
            severity=Severity.HIGH,
            reason="Anchor text shows one domain but the href points elsewhere.",
            evidence=f"text={anchor_dom} vs href={href_dom} ({link.href})",
        )
    ]


def detect_raw_ip(link: Link, _from_dom: str | None) -> list[Finding]:
    host = _href_host(link.href)
    if not host or not is_ip_literal(host):
        return []
    return [
        Finding(
            id="LINK.RAW_IP",
            title="Link points to a raw IP address",
            severity=Severity.MEDIUM,
            reason="The href host is a bare IP literal rather than a domain.",
            evidence=f"host={host} ({link.href})",
        )
    ]


def detect_punycode_idn(link: Link, _from_dom: str | None) -> list[Finding]:
    host = _href_host(link.href)
    if not host:
        return []
    puny = _is_punycode(host)
    mixed = _is_mixed_script(host)
    if not puny and not mixed:
        return []
    note = "punycode (xn--) label" if puny else "mixed-script host labels"
    return [
        Finding(
            id="LINK.PUNYCODE_IDN",
            title="Link host uses punycode / IDN homograph",
            severity=Severity.HIGH,
            reason="The href host uses an internationalized/punycode form.",
            evidence=f"host={host} [{note}] ({link.href})",
        )
    ]


def detect_shortener(link: Link, _from_dom: str | None) -> list[Finding]:
    href_dom = registrable_domain(link.href)
    if href_dom is None or href_dom not in _SHORTENERS:
        return []
    return [
        Finding(
            id="LINK.SHORTENER",
            title="Link uses a URL shortener",
            severity=Severity.LOW,
            reason="The href uses a known URL-shortening service (not expanded).",
            evidence=f"shortener={href_dom} ({link.href})",
        )
    ]


def detect_cred_keyword(link: Link, _from_dom: str | None) -> list[Finding]:
    parts = urlsplit(link.href)
    haystack = f"{parts.path}?{parts.query}"
    m = _CRED_RE.search(haystack)
    if not m:
        return []
    return [
        Finding(
            id="LINK.CRED_KEYWORD",
            title="Link path contains credential-harvest keyword",
            severity=Severity.LOW,
            reason="The href path/query contains a credential-related keyword.",
            evidence=f"keyword={m.group(1).lower()} ({link.href})",
        )
    ]


def detect_sender_domain_mismatch(link: Link, from_dom: str | None) -> list[Finding]:
    if from_dom is None:
        return []
    href_dom = registrable_domain(link.href)
    if href_dom is None or href_dom == from_dom:
        return []
    return [
        Finding(
            id="LINK.SENDER_DOMAIN_MISMATCH",
            title="Link domain differs from sender domain",
            severity=Severity.INFO,
            reason="The href domain differs from the From address domain.",
            evidence=f"href={href_dom} vs from={from_dom} ({link.href})",
        )
    ]


_PER_LINK_DETECTORS = (
    detect_href_text_mismatch,
    detect_raw_ip,
    detect_punycode_idn,
    detect_shortener,
    detect_cred_keyword,
    detect_sender_domain_mismatch,
)


def detect_links(parsed: ParsedEmail) -> list[Finding]:
    from_dom = (
        registrable_domain(parsed.from_addr) if parsed.from_addr else None
    )
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for link in parsed.links:
        for detector in _PER_LINK_DETECTORS:
            for finding in detector(link, from_dom):
                key = (finding.id, link.href)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
    return findings
