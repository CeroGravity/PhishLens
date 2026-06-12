"""Minimal header-anomaly detectors. No re-derivation of auth verdicts."""

from __future__ import annotations

from phishlens.models import Finding, ParsedEmail, Severity


def detect_missing_message_id(parsed: ParsedEmail) -> list[Finding]:
    if "message-id" in parsed.headers.raw:
        return []
    return [
        Finding(
            id="HDR.MISSING_MESSAGE_ID",
            title="Missing Message-ID header",
            severity=Severity.LOW,
            reason="The message has no Message-ID header.",
            evidence=None,
        )
    ]


def detect_multiple_from(parsed: ParsedEmail) -> list[Finding]:
    count = len(parsed.headers.raw.get("from", []))
    if count <= 1:
        return []
    return [
        Finding(
            id="HDR.MULTIPLE_FROM",
            title="Multiple From headers",
            severity=Severity.HIGH,
            reason="More than one From header is present.",
            evidence=f"from_count={count}",
        )
    ]


def detect_header_anomalies(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    findings += detect_missing_message_id(parsed)
    findings += detect_multiple_from(parsed)
    return findings
