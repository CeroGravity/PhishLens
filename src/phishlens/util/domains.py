"""Domain / host utilities. Strings only, deterministic, zero network.

`tldextract` is pinned offline: no live suffix-list fetch, no cache dir.
Registrable-domain comparison (not host comparison) is what identity and
link heuristics rely on, so `mail.example.com` and `example.com` match and
multi-label suffixes like `co.uk` are handled correctly.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

import tldextract

# RFC 6761 / RFC 2606 reserved TLDs. These are intentionally absent from the
# public suffix list, so the PSL snapshot would treat `foo.test` as having no
# suffix. PhishLens fixtures (CLAUDE.md §5) live in `.test`/`.invalid`/etc., so
# we register them as suffixes to get correct registrable-domain behavior on
# synthetic samples. Still fully offline and deterministic.
_RESERVED_SUFFIXES = ("test", "invalid", "example", "localhost")

# Offline, deterministic: bundled snapshot only, live fetch disabled,
# no cache directory. Must make zero network calls.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    extra_suffixes=_RESERVED_SUFFIXES,
)


def is_ip_literal(host: str) -> bool:
    """True if ``host`` is an IPv4 or IPv6 literal (brackets allowed)."""
    if not host:
        return False
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def host_of(url: str) -> str | None:
    """Hostname of a URL, lowercased, no network. None if absent.

    Accepts scheme-less inputs by assuming an http scheme so a bare
    ``www.example.com/path`` still yields a host.
    """
    if not url:
        return None
    candidate = url.strip()
    parsed = urlsplit(candidate)
    if not parsed.netloc and "://" not in candidate:
        parsed = urlsplit("http://" + candidate)
    host = parsed.hostname
    return host.lower() if host else None


def registrable_domain(host_or_url: str) -> str | None:
    """Registrable domain (``domain+suffix``) for a host or URL.

    Strips scheme/path, lowercases. IP literals and empty/suffix-less inputs
    return None. Deterministic; no network.
    """
    if not host_or_url:
        return None
    host = host_of(host_or_url) or host_or_url.strip().lower()
    if not host:
        return None
    if is_ip_literal(host):
        return None
    ext = _EXTRACT(host)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def sld_of(host_or_url: str) -> str | None:
    """Second-level-domain label (registrable domain minus public suffix).

    e.g. ``mail.example.co.uk`` -> ``example``. None for IPs / suffix-less.
    """
    if not host_or_url:
        return None
    host = host_of(host_or_url) or host_or_url.strip().lower()
    if not host or is_ip_literal(host):
        return None
    ext = _EXTRACT(host)
    if not ext.domain or not ext.suffix:
        return None
    return ext.domain
