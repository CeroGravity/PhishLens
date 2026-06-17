# PhishLens — Threat Model

## Defensive scope & authorization

PhishLens is a **defensive, purely analytical** tool. It inspects an artifact
the operator already possesses — an email they received (`.eml`) or a URL they
were sent — and produces an explainable risk report. It performs **no offensive
action** and requires no target authorization beyond the operator's own inbox.

Use is limited to inspecting messages/URLs the operator is authorized to
inspect (their own mail, mail reported to them, samples in an authorized
phishing-analysis context).

## Hard network boundary (non-negotiable)

PhishLens **never**:

- **Sends** anything — no email, callbacks, beacons, or read receipts.
- **Dereferences / fetches / expands** a URL found in a message or under
  analysis. URLs are treated as **strings only**. No HEAD, GET, redirect
  following, or shortener resolution.
- **Executes, extracts, decompresses, opens, or renders** attachments.
  Attachment analysis is filename + declared MIME + size + static extension
  metadata only. Payload bytes are read into memory **only** to measure size.

The default mode is **offline** (`--offline`): no network at all.

### What `--online` is — and is not

`--online` enables **only metadata lookups about a domain**, never contact with
the suspicious host or any message URL:

- **RDAP** registration-date lookup (domain age) — queries a registry about a
  domain via the RDAP client's fixed base URL (`https://rdap.org/domain/<d>`),
  not the message's links.
- **DKIM public-key DNS** — fetches the signer's published key to re-verify a
  DKIM signature cryptographically.

Both are injectable and degrade gracefully to "unknown" on failure.

## Trust assumptions

- PhishLens **trusts the receiver's stamped `Authentication-Results`** header
  for SPF/DKIM/DMARC verdicts. It does not re-run SPF or evaluate DKIM crypto
  offline.
- Optional `--online` adds independent checks: it re-verifies DKIM
  cryptographically (against the published key) and checks domain age.
- Alignment is **DMARC relaxed** (registrable-domain) alignment, computed from
  the stamped domains.

## Determinism

Identical input produces an identical report. There is no randomness and no
time-dependent verdict, with two scoped exceptions:

- `generated_at` — the report timestamp, built once at the CLI boundary.
- Domain age — computed against a reference date; the CLI supplies "now", and
  the report records the reference date in each domain-age finding's evidence.

Every verdict is an explicit `Finding` (id, severity, human-readable reason,
evidence). The risk score is transparent weighted addition over those findings
with documented severity weights and category thresholds — no ML, no hidden
scoring.

## Limitations

- **Brand-list coverage**: typosquat/brand-spoof detection only covers brands in
  the shipped list (or a `--brands` file). Unknown brands are not detected.
- **No live URL analysis / sandbox detonation**: URLs are never visited, so
  cloaking, redirect chains, and payload behavior are invisible by design.
- **Metadata-only attachments**: a file named `invoice.pdf` could still be
  anything; PhishLens cannot see inside archives or Office containers and does
  not claim to (no encrypted-archive or macro-content detection).
- **Typosquat heuristics**: edit-distance/homoglyph/combosquat matching yields
  both false positives and false negatives; findings are signals, not proof.
- **Stamped-verdict trust**: offline auth findings are only as trustworthy as
  the receiving MTA's `Authentication-Results`. `--online` mitigates this for
  DKIM.
