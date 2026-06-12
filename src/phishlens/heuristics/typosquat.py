"""Brand-aware detectors: typosquat, tld-swap, combosquat, display spoof.

Strings only — never fetch or resolve any domain. Brands are injectable so
tests can use a synthetic `.test` brand map.
"""

from __future__ import annotations

from collections.abc import Sequence

from phishlens.data.brands import Brand, load_brands
from phishlens.models import Finding, ParsedEmail, Severity
from phishlens.util.domains import registrable_domain, sld_of
from phishlens.util.typosquat import is_combosquat, is_typosquat


def _brand_legit_domains(brand: Brand) -> set[str]:
    """Legit registrable domains for a brand."""
    out: set[str] = set()
    for d in brand.domains:
        reg = registrable_domain(d)
        if reg:
            out.add(reg)
    return out


def _brand_slds(brand: Brand) -> set[str]:
    out: set[str] = set()
    for d in brand.domains:
        s = sld_of(d)
        if s:
            out.add(s)
    return out


def _classify_domain(
    candidate_reg: str | None,
    candidate_sld: str | None,
    brands: Sequence[Brand],
) -> list[tuple[str, str, Severity, str]]:
    """Return (finding_id, brand_name, severity, match_note) tuples.

    Never classifies an exact legit registrable domain.
    """
    results: list[tuple[str, str, Severity, str]] = []
    if not candidate_reg or not candidate_sld:
        return results

    for brand in brands:
        legit = _brand_legit_domains(brand)
        if candidate_reg in legit:
            continue  # exact legit domain — never flag

        brand_slds = _brand_slds(brand)

        # typosquat / homoglyph
        if any(is_typosquat(candidate_sld, bsld) for bsld in brand_slds):
            results.append(
                ("LINK.TYPOSQUAT", brand.name, Severity.HIGH, "edit/homoglyph")
            )
            continue

        # tld-swap: same sld as the brand, different suffix than any legit
        if candidate_sld in brand_slds:
            results.append(
                ("LINK.TLD_SWAP", brand.name, Severity.HIGH, "tld-swap")
            )
            continue

        # combosquat: brand sld/alias token embedded in a longer sld
        tokens = set(brand_slds)
        tokens.update(a.replace(" ", "") for a in brand.aliases)
        if any(is_combosquat(candidate_sld, t) for t in tokens):
            results.append(
                ("LINK.COMBOSQUAT", brand.name, Severity.MEDIUM, "combosquat")
            )
            continue

    return results


def _domain_findings(
    reg: str | None,
    sld: str | None,
    source: str,
    brands: Sequence[Brand],
) -> list[tuple[str, str, Severity, str, str]]:
    """(id, brand, severity, note, target) per classified hit."""
    out: list[tuple[str, str, Severity, str, str]] = []
    for fid, brand, sev, note in _classify_domain(reg, sld, brands):
        out.append((fid, brand, sev, note, source))
    return out


def detect_display_brand_spoof(
    parsed: ParsedEmail,
    brands: Sequence[Brand],
) -> list[Finding]:
    if not parsed.from_display:
        return []
    from_reg = registrable_domain(parsed.from_addr) if parsed.from_addr else None
    if from_reg is None:
        return []
    display = parsed.from_display.lower()
    findings: list[Finding] = []
    seen: set[str] = set()
    for brand in brands:
        if brand.name in seen:
            continue
        if any(alias in display for alias in brand.aliases):
            if from_reg not in _brand_legit_domains(brand):
                seen.add(brand.name)
                findings.append(
                    Finding(
                        id="IDENT.DISPLAY_BRAND_SPOOF",
                        title="Display name impersonates a brand",
                        severity=Severity.HIGH,
                        reason=(
                            "Display name references a known brand but the "
                            "From domain is not one of that brand's domains."
                        ),
                        evidence=f"brand={brand.name} from={from_reg}",
                    )
                )
    return findings


def detect_brands(
    parsed: ParsedEmail,
    *,
    brands: Sequence[Brand] | None = None,
) -> list[Finding]:
    brand_list = list(brands) if brands is not None else list(load_brands())

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    # Candidate targets: sender registrable domain + each link registrable.
    targets: list[tuple[str, str | None]] = []
    if parsed.from_addr:
        targets.append(("from", parsed.from_addr))
    for link in parsed.links:
        targets.append(("link", link.href))

    for source, raw in targets:
        if raw is None:
            continue
        reg = registrable_domain(raw)
        sld = sld_of(raw)
        for fid, brand, sev, note, _src in _domain_findings(
            reg, sld, source, brand_list
        ):
            key = (fid, brand, reg or raw)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    id=fid,
                    title=_title_for(fid),
                    severity=sev,
                    reason=_reason_for(fid, brand),
                    evidence=f"brand={brand} target={reg} ({note}, {source})",
                )
            )

    findings += detect_display_brand_spoof(parsed, brand_list)
    return findings


def _title_for(fid: str) -> str:
    return {
        "LINK.TYPOSQUAT": "Domain typosquats a known brand",
        "LINK.TLD_SWAP": "Domain swaps the TLD of a known brand",
        "LINK.COMBOSQUAT": "Domain combosquats a known brand",
    }[fid]


def _reason_for(fid: str, brand: str) -> str:
    return {
        "LINK.TYPOSQUAT": (
            f"Domain closely resembles {brand} (typo/homoglyph) but is not a "
            f"legitimate {brand} domain."
        ),
        "LINK.TLD_SWAP": (
            f"Domain reuses the {brand} name under a different TLD."
        ),
        "LINK.COMBOSQUAT": (
            f"Domain embeds the {brand} name with extra characters."
        ),
    }[fid]
