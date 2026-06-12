"""PhishLens command-line interface.

Phase 0: argument wiring only. `analyze` prints a not-yet-implemented
notice and exits 0. No parsing, no network.
"""

from __future__ import annotations

import argparse


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
        "eml",
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
        help="Enable metadata-only network lookups (DNS / RDAP about a domain).",
    )

    analyze.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="markdown",
        help="Output format (default: markdown).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        mode = "offline" if args.offline else "online"
        target = args.url if args.url else args.eml
        print(
            f"phishlens analyze: not yet implemented "
            f"(target={target!r}, mode={mode}, format={args.format})"
        )
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
