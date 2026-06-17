"""PhishLens command-line interface.

Wires the offline pipeline (and, under --online, RDAP domain-age + DKIM crypto
verification) into a rendered report. This is the ONLY place an implicit clock
is allowed (generated_at). PhishLens never sends anything, never fetches or
expands a URL found in / under analysis, and never executes attachments.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, date, datetime

from phishlens.app import analyze_email, analyze_url
from phishlens.auth.dkim_verify import DnsFunc
from phishlens.data.brands import (
    Brand,
    BrandFileError,
    load_brands,
    load_brands_from_file,
)
from phishlens.enrich.rdap import HttpxRdapClient, RdapClient
from phishlens.report import render_json, render_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="Defensive, purely analytical phishing-analysis tool.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a .eml file or a URL string.",
    )

    source = analyze.add_mutually_exclusive_group(required=False)
    source.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to a raw .eml file to analyze.",
    )
    source.add_argument(
        "--url",
        default=None,
        help="A URL string to analyze (treated as a string only; never fetched).",
    )

    mode = analyze.add_mutually_exclusive_group()
    mode.add_argument(
        "--offline",
        dest="offline",
        action="store_true",
        default=True,
        help="No network at all (default).",
    )
    mode.add_argument(
        "--online",
        dest="offline",
        action="store_false",
        help="Enable metadata-only lookups (RDAP domain-age + DKIM key DNS).",
    )

    analyze.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    analyze.add_argument(
        "--brands",
        default=None,
        help="Path to a JSON brand list (defaults to the shipped list).",
    )

    return parser


def _dkim_dnsfunc() -> DnsFunc:
    """Real DKIM public-key DNS lookup via dkimpy's default resolver."""

    def dnsfunc(name: str, **kwargs: object) -> object:
        import dkim

        return dkim.dnsplug.get_txt(name)

    return dnsfunc


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "analyze":
        parser.print_help()
        return 0

    if bool(args.target) == bool(args.url):
        parser.error("provide exactly one of: a .eml path or --url URL")
        return 2  # argparse.error exits 2; this is for type-checkers

    # Resolve brand list.
    brands: tuple[Brand, ...]
    if args.brands is not None:
        try:
            brands = load_brands_from_file(args.brands)
        except BrandFileError as exc:
            parser.error(str(exc))
            return 2
    else:
        brands = load_brands()

    online = not args.offline
    generated_at = datetime.now(UTC).isoformat()
    now: date | None = datetime.now(UTC).date() if online else None

    rdap_client: RdapClient | None = HttpxRdapClient() if online else None
    dnsfunc: DnsFunc | None = _dkim_dnsfunc() if online else None

    try:
        if args.url:
            report = analyze_url(
                args.url,
                generated_at=generated_at,
                online=online,
                brands=brands,
                rdap_client=rdap_client,
                now=now,
            )
        else:
            report = analyze_email(
                args.target,
                generated_at=generated_at,
                online=online,
                brands=brands,
                rdap_client=rdap_client,
                dnsfunc=dnsfunc,
                now=now,
            )
    except FileNotFoundError as exc:
        parser.error(f"file not found: {exc.filename}")
        return 2
    except Exception as exc:  # unexpected internal error
        print(f"phishlens: internal error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(render_json(report))
    else:
        print(render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
