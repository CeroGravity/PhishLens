"""Bundled brand list for brand-spoof / typosquat detection.

`aliases` are lowercased display-name tokens; `domains` are legitimate
registrable domains. Detectors accept an injectable brands tuple so tests can
supply synthetic `.test` brands (CLAUDE.md §5). No network.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    aliases: tuple[str, ...]
    domains: tuple[str, ...]


_BRANDS: tuple[Brand, ...] = (
    Brand("paypal", ("paypal",), ("paypal.com",)),
    Brand(
        "microsoft",
        ("microsoft", "office365", "outlook"),
        ("microsoft.com", "microsoftonline.com", "live.com"),
    ),
    Brand("apple", ("apple", "icloud", "appleid"), ("apple.com", "icloud.com")),
    Brand("amazon", ("amazon", "aws"), ("amazon.com", "aws.amazon.com")),
    Brand("google", ("google", "gmail"), ("google.com", "gmail.com")),
    Brand("netflix", ("netflix",), ("netflix.com",)),
    Brand("facebook", ("facebook", "meta"), ("facebook.com", "fb.com")),
    Brand("instagram", ("instagram",), ("instagram.com",)),
    Brand("linkedin", ("linkedin",), ("linkedin.com",)),
    Brand("whatsapp", ("whatsapp",), ("whatsapp.com",)),
    Brand("dropbox", ("dropbox",), ("dropbox.com",)),
    Brand("docusign", ("docusign",), ("docusign.com",)),
    Brand("adobe", ("adobe",), ("adobe.com",)),
    Brand("dhl", ("dhl",), ("dhl.com",)),
    Brand("fedex", ("fedex",), ("fedex.com",)),
    Brand("ups", ("ups",), ("ups.com",)),
    Brand("chase", ("chase", "jpmorgan"), ("chase.com",)),
    Brand("wellsfargo", ("wells fargo", "wellsfargo"), ("wellsfargo.com",)),
    Brand(
        "bankofamerica",
        ("bank of america", "bofa"),
        ("bankofamerica.com",),
    ),
    Brand(
        "amex",
        ("american express", "amex"),
        ("americanexpress.com", "amex.com"),
    ),
)


def load_brands() -> tuple[Brand, ...]:
    """Return the shipped brand list."""
    return _BRANDS
