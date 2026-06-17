"""Adapter: AuthResult (Phase 2 data) -> evaluative Findings.

This is the deliberately-deferred conversion of stamped auth verdicts into
findings. It does NOT re-derive any verdict — it only reads AuthResult. The
online DKIM crypto failure (AUTH.DKIM_VERIFY_FAIL) is produced by the Phase-5
path and is intentionally NOT duplicated here.
"""

from __future__ import annotations

from phishlens.models import AuthResult, Finding, Severity


def auth_to_findings(auth: AuthResult | None) -> list[Finding]:
    if auth is None:
        return []

    findings: list[Finding] = []

    if auth.dmarc == "fail":
        findings.append(
            Finding(
                id="AUTH.DMARC_FAIL",
                title="DMARC evaluation failed",
                severity=Severity.HIGH,
                reason="The receiving server reported a DMARC failure.",
                evidence="dmarc=fail",
            )
        )

    if auth.spf in {"fail", "softfail"}:
        findings.append(
            Finding(
                id="AUTH.SPF_FAIL",
                title="SPF evaluation failed",
                severity=Severity.MEDIUM,
                reason="The receiving server reported an SPF failure/softfail.",
                evidence=f"spf={auth.spf}",
            )
        )

    if auth.dkim == "fail":
        findings.append(
            Finding(
                id="AUTH.DKIM_FAIL",
                title="DKIM evaluation failed",
                severity=Severity.MEDIUM,
                reason="The receiving server reported a DKIM failure.",
                evidence="dkim=fail",
            )
        )

    if auth.aligned is False:
        findings.append(
            Finding(
                id="AUTH.NOT_ALIGNED",
                title="From domain not aligned with authenticated domain",
                severity=Severity.MEDIUM,
                reason=(
                    "The From domain is not aligned (relaxed) with the SPF or "
                    "DKIM authenticated domain."
                ),
                evidence="aligned=False",
            )
        )

    if auth.spf is None and auth.dkim is None and auth.dmarc is None:
        findings.append(
            Finding(
                id="AUTH.NO_AUTH",
                title="No authentication results present",
                severity=Severity.LOW,
                reason="The message carries no SPF/DKIM/DMARC authentication results.",
                evidence=None,
            )
        )

    return findings
