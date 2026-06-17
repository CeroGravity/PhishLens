"""Attachment risk flags from static metadata ONLY.

Operates on Attachment objects already extracted in Phase 1 (filename,
content_type, size, extensions). No decompression, no container opening, no
macro-byte inspection, no execution, no re-reading the .eml, and no payload
byte access beyond the size already measured (CLAUDE.md §3.4). Offline,
deterministic, case-insensitive filename matching.
"""

from __future__ import annotations

from phishlens.models import Attachment, Finding, ParsedEmail, Severity

_DANGEROUS_EXT = frozenset(
    {
        "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe",
        "wsf", "wsh", "hta", "jar", "ps1", "msi", "cpl", "lnk", "reg", "dll",
        "vhd",
    }
)

# Common "lure" doc/media types used to disguise the real final extension.
_LURE_EXT = frozenset(
    {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg",
        "jpeg", "png", "gif",
    }
)

_MACRO_EXT = frozenset(
    {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "potm"}
)

_ARCHIVE_EXT = frozenset(
    {"zip", "rar", "7z", "gz", "tar", "bz2", "iso", "img"}
)

# Conservative ext -> expected (maintype, subtype) map. Only recognized pairs
# are compared; unknowns and octet-stream are never flagged as a mismatch.
_EXPECTED_TYPE: dict[str, tuple[str, str]] = {
    "jpg": ("image", "jpeg"),
    "jpeg": ("image", "jpeg"),
    "png": ("image", "png"),
    "gif": ("image", "gif"),
    "pdf": ("application", "pdf"),
    "txt": ("text", "plain"),
    "zip": ("application", "zip"),
}

_GENERIC_TYPES = frozenset({"application/octet-stream"})


def _final_ext(att: Attachment) -> str | None:
    if not att.extensions:
        return None
    return att.extensions[-1].lower()


def detect_dangerous_extension(att: Attachment) -> list[Finding]:
    ext = _final_ext(att)
    if ext is None or ext not in _DANGEROUS_EXT:
        return []
    return [
        Finding(
            id="ATTACH.DANGEROUS_EXTENSION",
            title="Attachment has an executable/script extension",
            severity=Severity.HIGH,
            reason="The attachment's final extension is an executable or script type.",
            evidence=f"filename={att.filename} ext=.{ext}",
        )
    ]


def detect_double_extension(att: Attachment) -> list[Finding]:
    if len(att.extensions) < 2:
        return []
    penultimate = att.extensions[-2].lower()
    if penultimate not in _LURE_EXT:
        return []
    return [
        Finding(
            id="ATTACH.DOUBLE_EXTENSION",
            title="Attachment uses a deceptive double extension",
            severity=Severity.HIGH,
            reason=(
                "The filename hides its real type behind a document/media "
                "extension (e.g. invoice.pdf.exe)."
            ),
            evidence=f"filename={att.filename} extensions={att.extensions}",
        )
    ]


def detect_macro_enabled(att: Attachment) -> list[Finding]:
    ext = _final_ext(att)
    if ext is None or ext not in _MACRO_EXT:
        return []
    return [
        Finding(
            id="ATTACH.MACRO_ENABLED",
            title="Macro-enabled Office attachment",
            severity=Severity.MEDIUM,
            reason=(
                "The attachment extension is a macro-enabled Office type "
                "(by extension only; contents not inspected)."
            ),
            evidence=f"filename={att.filename} ext=.{ext}",
        )
    ]


def detect_content_type_mismatch(att: Attachment) -> list[Finding]:
    ext = _final_ext(att)
    if ext is None or att.content_type is None:
        return []
    if ext not in _EXPECTED_TYPE:
        return []
    ct = att.content_type.lower()
    if ct in _GENERIC_TYPES:
        return []  # generic declared type -> never a mismatch
    if "/" not in ct:
        return []
    maintype, _, subtype = ct.partition("/")
    if (maintype, subtype) == _EXPECTED_TYPE[ext]:
        return []
    return [
        Finding(
            id="ATTACH.CONTENT_TYPE_MISMATCH",
            title="Declared content type disagrees with file extension",
            severity=Severity.MEDIUM,
            reason="The declared Content-Type does not match the file extension.",
            evidence=(
                f"filename={att.filename} ext=.{ext} "
                f"declared={att.content_type}"
            ),
        )
    ]


def detect_archive(att: Attachment) -> list[Finding]:
    ext = _final_ext(att)
    if ext is None or ext not in _ARCHIVE_EXT:
        return []
    return [
        Finding(
            id="ATTACH.ARCHIVE",
            title="Archive attachment",
            severity=Severity.INFO,
            reason="The attachment is an archive; its contents are NOT inspected.",
            evidence=f"filename={att.filename} ext=.{ext} (contents not inspected)",
        )
    ]


def detect_no_extension(att: Attachment) -> list[Finding]:
    if att.filename is None or att.extensions:
        return []
    return [
        Finding(
            id="ATTACH.NO_EXTENSION",
            title="Attachment has no file extension",
            severity=Severity.LOW,
            reason="The attachment has a filename but no extension.",
            evidence=f"filename={att.filename}",
        )
    ]


_DETECTORS = (
    detect_dangerous_extension,
    detect_double_extension,
    detect_macro_enabled,
    detect_content_type_mismatch,
    detect_archive,
    detect_no_extension,
)


def detect_attachments(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str | None]] = set()
    for att in parsed.attachments:
        for detector in _DETECTORS:
            for finding in detector(att):
                key = (finding.id, att.filename)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
    return findings
