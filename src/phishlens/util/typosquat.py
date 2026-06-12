"""Pure-Python typosquat / homoglyph / combosquat classifiers. No new deps.

Operates on the SLD label (registrable domain minus public suffix) unless
noted. Strings only — never resolves or fetches any domain.
"""

from __future__ import annotations

# Minimum SLD length to consider — guards against trivially-short labels
# producing edit-distance-1 false positives.
MIN_SLD_LEN = 4


def levenshtein(a: str, b: str) -> int:
    """Iterative DP Levenshtein edit distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


# Small curated confusable map. Multi-char keys are applied before single
# char folds. Kept intentionally small and documented to limit false matches.
_MULTI_CONFUSABLES = (
    ("rn", "m"),
    ("vv", "w"),
)
_SINGLE_CONFUSABLES = {
    "0": "o",
    "1": "l",
    "5": "s",
    "3": "e",
    "4": "a",
    "7": "t",
    "$": "s",
    "|": "l",
}


def homoglyph_normalize(s: str) -> str:
    """Fold common visual confusables to a canonical lowercase form.

    Multi-character substitutions run first (e.g. 'rn'->'m'), then single
    character folds (e.g. '1'->'l', '0'->'o').
    """
    out = s.lower()
    for src, dst in _MULTI_CONFUSABLES:
        out = out.replace(src, dst)
    out = "".join(_SINGLE_CONFUSABLES.get(ch, ch) for ch in out)
    return out


def is_typosquat(sld: str, brand_sld: str) -> bool:
    """Candidate ≠ legit but edit-distance ≤ 1, or homoglyph-equal while raw
    forms differ."""
    if sld == brand_sld:
        return False
    if len(sld) < MIN_SLD_LEN or len(brand_sld) < MIN_SLD_LEN:
        return False
    if levenshtein(sld, brand_sld) <= 1:
        return True
    if homoglyph_normalize(sld) == homoglyph_normalize(brand_sld):
        return True
    return False


def is_combosquat(sld: str, brand_token: str) -> bool:
    """A brand alias/sld appears as a substring inside a longer candidate sld."""
    if len(brand_token) < MIN_SLD_LEN:
        return False
    if sld == brand_token:
        return False
    return brand_token in sld and len(sld) > len(brand_token)
