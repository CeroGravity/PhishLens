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


class BrandFileError(ValueError):
    """Raised when a --brands file is malformed."""


def load_brands_from_file(path: str) -> tuple[Brand, ...]:
    """Load brands from a JSON file: [{"name","aliases","domains"}, ...].

    Aliases/domains are lowercased. Raises BrandFileError on any shape problem.
    """
    import json

    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise BrandFileError(f"brands file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BrandFileError(f"brands file is not valid JSON: {exc}") from exc

    if not isinstance(data, list):
        raise BrandFileError("brands file must be a JSON array of objects")

    brands: list[Brand] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise BrandFileError(f"brand #{i} is not an object")
        name = entry.get("name")
        aliases = entry.get("aliases")
        domains = entry.get("domains")
        if not isinstance(name, str) or not name:
            raise BrandFileError(f"brand #{i} missing a string 'name'")
        if not isinstance(aliases, list) or not all(
            isinstance(a, str) for a in aliases
        ):
            raise BrandFileError(f"brand {name!r} 'aliases' must be a list of strings")
        if (
            not isinstance(domains, list)
            or not domains
            or not all(isinstance(d, str) for d in domains)
        ):
            raise BrandFileError(
                f"brand {name!r} 'domains' must be a non-empty list of strings"
            )
        brands.append(
            Brand(
                name=name.lower(),
                aliases=tuple(a.lower() for a in aliases),
                domains=tuple(d.lower() for d in domains),
            )
        )
    return tuple(brands)
