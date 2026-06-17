"""Deterministic markdown renderer. No network, no external assets."""

from __future__ import annotations

from phishlens.models import Report


def _escape(text: str) -> str:
    """Escape pipe characters so table cells stay well-formed."""
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append("# PhishLens Report")
    lines.append("")
    lines.append(f"- **Target:** {report.target}")
    lines.append(f"- **Mode:** {report.mode}")
    lines.append(f"- **Risk category:** {report.category.value}")
    lines.append(f"- **Score:** {report.score}")
    lines.append(f"- **Generated at:** {report.generated_at}")

    if report.auth is not None:
        a = report.auth
        lines.append("")
        lines.append(
            "- **Auth:** "
            f"spf={a.spf} dkim={a.dkim} dmarc={a.dmarc} aligned={a.aligned}"
        )

    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    lines.append("| Severity | ID | Reason | Evidence |")
    lines.append("| --- | --- | --- | --- |")
    for f in report.findings:
        evidence = _escape(f.evidence) if f.evidence else ""
        lines.append(
            f"| {f.severity.value} | {f.id} | {_escape(f.reason)} | {evidence} |"
        )

    return "\n".join(lines) + "\n"
