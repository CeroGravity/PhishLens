"""Phase 6 attachment-metadata detector tests. Metadata only, offline."""

from __future__ import annotations

from pathlib import Path

from phishlens.heuristics import run_identity_link
from phishlens.heuristics.attachments import detect_attachments
from phishlens.ingest.eml import load_eml
from phishlens.models import Attachment, HeaderSet, ParsedEmail, Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _ids(name: str) -> set[str]:
    return {f.id for f in detect_attachments(load_eml(str(FIXTURES / name)))}


def _sev(name: str) -> dict[str, Severity]:
    return {f.id: f.severity for f in detect_attachments(load_eml(str(FIXTURES / name)))}


def _att(
    filename: str | None,
    content_type: str | None,
    extensions: tuple[str, ...],
    size: int = 10,
) -> ParsedEmail:
    return ParsedEmail(
        headers=HeaderSet(raw={}),
        from_display=None,
        from_addr=None,
        reply_to=None,
        return_path=None,
        subject=None,
        text_body=None,
        html_body=None,
        links=[],
        attachments=[
            Attachment(
                filename=filename,
                content_type=content_type,
                size=size,
                extensions=extensions,
            )
        ],
    )


# --- fixture exact sets ----------------------------------------------------


def test_dangerous_double_extension() -> None:
    assert _ids("dangerous_attachment.eml") == {
        "ATTACH.DANGEROUS_EXTENSION",
        "ATTACH.DOUBLE_EXTENSION",
    }
    sev = _sev("dangerous_attachment.eml")
    assert sev["ATTACH.DANGEROUS_EXTENSION"] == Severity.HIGH
    assert sev["ATTACH.DOUBLE_EXTENSION"] == Severity.HIGH


def test_macro_enabled() -> None:
    assert _ids("attach_macro.eml") == {"ATTACH.MACRO_ENABLED"}
    assert _sev("attach_macro.eml")["ATTACH.MACRO_ENABLED"] == Severity.MEDIUM


def test_content_type_mismatch() -> None:
    assert _ids("attach_mismatch.eml") == {"ATTACH.CONTENT_TYPE_MISMATCH"}
    assert (
        _sev("attach_mismatch.eml")["ATTACH.CONTENT_TYPE_MISMATCH"]
        == Severity.MEDIUM
    )


def test_archive() -> None:
    assert _ids("attach_archive.eml") == {"ATTACH.ARCHIVE"}
    assert _sev("attach_archive.eml")["ATTACH.ARCHIVE"] == Severity.INFO


def test_no_extension() -> None:
    assert _ids("attach_noext.eml") == {"ATTACH.NO_EXTENSION"}
    assert _sev("attach_noext.eml")["ATTACH.NO_EXTENSION"] == Severity.LOW


def test_clean_control_zero() -> None:
    assert detect_attachments(load_eml(str(FIXTURES / "benign_plain.eml"))) == []


# --- behavior --------------------------------------------------------------


def test_case_insensitive() -> None:
    parsed = _att("INVOICE.PDF.EXE", "application/octet-stream", ("PDF", "EXE"))
    assert {f.id for f in detect_attachments(parsed)} == {
        "ATTACH.DANGEROUS_EXTENSION",
        "ATTACH.DOUBLE_EXTENSION",
    }


def test_octet_stream_not_mismatch() -> None:
    # .jpg declared as the generic octet-stream must NOT flag a mismatch.
    parsed = _att("photo.jpg", "application/octet-stream", ("jpg",))
    assert "ATTACH.CONTENT_TYPE_MISMATCH" not in {
        f.id for f in detect_attachments(parsed)
    }


def test_unknown_ext_not_mismatch() -> None:
    # Unknown extension on either side -> no mismatch (conservative).
    parsed = _att("data.bin", "image/png", ("bin",))
    assert detect_attachments(parsed) == []


def test_matching_type_not_mismatch() -> None:
    parsed = _att("photo.jpg", "image/jpeg", ("jpg",))
    assert detect_attachments(parsed) == []


def test_metadata_only_no_file_open(monkeypatch) -> None:
    # Detectors must operate purely on Attachment objects: never open a file,
    # never re-read the .eml. Trip-wire builtins.open.
    import builtins

    parsed = _att("invoice.pdf.exe", "application/octet-stream", ("pdf", "exe"))

    def _boom(*args, **kwargs):
        raise AssertionError("attachment detector opened a file")

    monkeypatch.setattr(builtins, "open", _boom)
    findings = detect_attachments(parsed)
    assert {f.id for f in findings} == {
        "ATTACH.DANGEROUS_EXTENSION",
        "ATTACH.DOUBLE_EXTENSION",
    }


def test_no_encrypted_archive_detector() -> None:
    # Confirm no detector claims encrypted-archive detection.
    from phishlens.heuristics import attachments

    src = Path(attachments.__file__).read_text(encoding="utf-8")
    assert "ENCRYPTED" not in src.upper()


def test_determinism_order_included() -> None:
    p = load_eml(str(FIXTURES / "dangerous_attachment.eml"))
    a = detect_attachments(p)
    b = detect_attachments(p)
    assert a == b
    assert [f.id for f in a] == [f.id for f in b]


def test_collector_includes_attachment_findings_list_only() -> None:
    findings = run_identity_link(
        load_eml(str(FIXTURES / "dangerous_attachment.eml"))
    )
    ids = {f.id for f in findings}
    assert "ATTACH.DANGEROUS_EXTENSION" in ids
    assert isinstance(findings, list)
    assert not hasattr(findings, "score")
    assert not hasattr(findings, "category")
