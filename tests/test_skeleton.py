"""Phase 0 skeleton tests: imports, CLI wiring, fixture presence."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
SYNTHETIC_MARKER = "X-Synthetic-Fixture:"
FIXTURE_NAMES = (
    "benign_plain.eml",
    "spoof_displayname.eml",
    "dangerous_attachment.eml",
)


@pytest.mark.parametrize(
    "module",
    [
        "phishlens",
        "phishlens.models",
        "phishlens.cli",
        "phishlens.ingest",
        "phishlens.parsers",
        "phishlens.auth",
        "phishlens.heuristics",
        "phishlens.scoring",
        "phishlens.report",
    ],
)
def test_subpackages_import(module: str) -> None:
    importlib.import_module(module)


def test_cli_builds_parser() -> None:
    from phishlens.cli import build_parser

    parser = build_parser()
    assert parser.prog == "phishlens"


def test_analyze_help_does_not_raise() -> None:
    from phishlens.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["analyze", "--help"])
    assert exc.value.code == 0


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_present_and_synthetic(name: str) -> None:
    path = FIXTURES / name
    assert path.is_file(), f"missing fixture {name}"
    first_line = path.read_text(encoding="utf-8").splitlines()[0]
    assert first_line.startswith(SYNTHETIC_MARKER), (
        f"{name} missing synthetic marker on first line"
    )
