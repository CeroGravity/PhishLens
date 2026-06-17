"""Phase 8 CLI tests. Offline; online seam driven by injected fakes."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from phishlens import app, cli
from phishlens.data.brands import Brand

FIXTURES = Path(__file__).parent / "fixtures"
GEN = "2024-06-01T00:00:00Z"
NOW = date(2024, 6, 1)


# --- CLI offline -----------------------------------------------------------


def test_eml_json_exit0(capsys) -> None:
    rc = cli.main(["analyze", str(FIXTURES / "link_mismatch.eml"), "--format", "json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["category"] == "HIGH"
    assert "findings" in out


def test_eml_markdown_shows_category_score(capsys) -> None:
    rc = cli.main(["analyze", str(FIXTURES / "link_mismatch.eml")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Risk category:" in out
    assert "Score:" in out


def test_url_mode_no_sender_detectors(capsys) -> None:
    rc = cli.main(["analyze", "--url", "http://192.0.2.5/login", "--format", "json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    ids = {f["id"] for f in out["findings"]}
    # Sender / identity / auth / header detectors must not appear in URL mode.
    assert "LINK.SENDER_DOMAIN_MISMATCH" not in ids
    assert "HDR.MISSING_MESSAGE_ID" not in ids
    assert all(not i.startswith(("IDENT.", "AUTH.")) for i in ids)
    assert "LINK.RAW_IP" in ids
    assert out["auth"] is None


def test_missing_target_exit2() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["analyze"])
    assert exc.value.code == 2


def test_both_target_and_url_exit2() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["analyze", "x.eml", "--url", "http://a.test"])
    assert exc.value.code == 2


def test_missing_file_exit2() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["analyze", str(FIXTURES / "does_not_exist.eml")])
    assert exc.value.code == 2


# --- brand file ------------------------------------------------------------


def test_brands_file_applied(tmp_path, capsys) -> None:
    brands = tmp_path / "brands.json"
    brands.write_text(
        json.dumps(
            [{"name": "examplebank", "aliases": ["example bank"],
              "domains": ["examplebank.test"]}]
        )
    )
    rc = cli.main(
        ["analyze", "--url", "https://examp1ebank.test/", "--format", "json",
         "--brands", str(brands)]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "LINK.TYPOSQUAT" in {f["id"] for f in out["findings"]}


def test_brands_file_malformed_exit2(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json")
    with pytest.raises(SystemExit) as exc:
        cli.main(["analyze", "--url", "http://a.test", "--brands", str(bad)])
    assert exc.value.code == 2


def test_brands_file_wrong_shape_exit2(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"name": "x"}]))  # missing aliases/domains
    with pytest.raises(SystemExit) as exc:
        cli.main(["analyze", "--url", "http://a.test", "--brands", str(bad)])
    assert exc.value.code == 2


# --- online seam (injected fakes) ------------------------------------------


class _FakeRdap:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def creation_date(self, domain):
        self.calls.append(domain)
        return self.mapping.get(domain)


def test_app_online_seam_domain_age() -> None:
    client = _FakeRdap({"sender.test": NOW - timedelta(days=5)})

    def fake_dnsfunc(name, **kwargs):
        return b""  # no key -> verify fails undetermined, never real DNS

    app.analyze_email(
        str(FIXTURES / "auth_pass.eml"),
        generated_at=GEN,
        online=True,
        rdap_client=client,
        now=NOW,
        dnsfunc=fake_dnsfunc,
    )
    # auth_pass sender is example.com (unknown to fake) -> no domain-age finding,
    # but the client WAS consulted for online enrichment (registry metadata).
    assert client.calls != []


def test_app_url_online_domain_age_finding() -> None:
    client = _FakeRdap({"new.test": NOW - timedelta(days=3)})
    report = app.analyze_url(
        "https://new.test/login",
        generated_at=GEN,
        online=True,
        rdap_client=client,
        now=NOW,
    )
    ids = {f.id for f in report.findings}
    assert "DOMAIN.NEWLY_REGISTERED" in ids
    assert client.calls == ["new.test"]


def test_offline_default_zero_rdap_calls() -> None:
    client = _FakeRdap({"new.test": NOW - timedelta(days=3)})
    report = app.analyze_url(
        "https://new.test/login",
        generated_at=GEN,
        online=False,
        rdap_client=client,
        now=NOW,
    )
    assert client.calls == []
    assert "DOMAIN.NEWLY_REGISTERED" not in {f.id for f in report.findings}


# --- determinism -----------------------------------------------------------


def test_determinism_byte_identical_json() -> None:
    custom: tuple[Brand, ...] = ()
    a = app.analyze_email(
        str(FIXTURES / "link_mismatch.eml"), generated_at=GEN, brands=custom
    )
    b = app.analyze_email(
        str(FIXTURES / "link_mismatch.eml"), generated_at=GEN, brands=custom
    )
    from phishlens.report import render_json

    assert render_json(a) == render_json(b)
