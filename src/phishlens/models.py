"""Data contracts for PhishLens reports.

Phase 0: types only. No detection behavior beyond trivial helpers.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskCategory(enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: Severity
    reason: str
    evidence: str | None = None


@dataclass
class HeaderSet:
    raw: dict[str, list[str]]

    def get(self, name: str) -> str | None:
        """Return first value for a header, case-insensitive."""
        target = name.lower()
        for key, values in self.raw.items():
            if key.lower() == target:
                return values[0] if values else None
        return None


@dataclass(frozen=True)
class Link:
    href: str
    anchor_text: str | None
    source: str  # "html" | "text"


@dataclass(frozen=True)
class Attachment:
    filename: str | None
    content_type: str | None
    size: int
    extensions: tuple[str, ...]


@dataclass
class AuthResult:
    spf: str | None
    dkim: str | None
    dmarc: str | None
    spf_domain: str | None
    dkim_domain: str | None
    aligned: bool | None


@dataclass
class ParsedEmail:
    headers: HeaderSet
    from_display: str | None
    from_addr: str | None
    reply_to: str | None
    return_path: str | None
    subject: str | None
    text_body: str | None
    html_body: str | None
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)


@dataclass
class Report:
    target: str
    mode: str
    category: RiskCategory
    score: int
    findings: list[Finding]
    auth: AuthResult | None
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "mode": self.mode,
            "category": self.category.value,
            "score": self.score,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "reason": f.reason,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
            "auth": (
                {
                    "spf": self.auth.spf,
                    "dkim": self.auth.dkim,
                    "dmarc": self.auth.dmarc,
                    "spf_domain": self.auth.spf_domain,
                    "dkim_domain": self.auth.dkim_domain,
                    "aligned": self.auth.aligned,
                }
                if self.auth is not None
                else None
            ),
            "generated_at": self.generated_at,
        }
