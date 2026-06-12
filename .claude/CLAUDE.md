# CLAUDE.md — PhishLens

> Project-specific governance. Supersedes the generic cybersec CLAUDE.md where they conflict. Read fully before any action in this repo.
## Response Style (Always Strict - Exception Report & Manual Checklist)

- Use 3-6 word sentences.
- No filler or preamble.
- No pleasantries.
- Drop articles. ("Me fix code.")
- Run tools first. Show result. Stop.
- No narration around tools.

## 1. Project identity

PhishLens is a **defensive, purely analytical** phishing-analysis tool.

Input: a raw `.eml` file **or** a URL string.
Output: a deterministic, explainable risk report covering SPF/DKIM/DMARC results, header analysis, display-name mismatch, link extraction, typosquat / domain-age detection, and attachment flags.

PhishLens **explains** why a message looks malicious. It never acts on the message.

## 2. Authorization & scope

- This tool analyzes artifacts the operator already possesses (an email they received, a URL they were sent). It performs no offensive action and requires no target authorization beyond the operator's own inbox.
- Use is limited to **inspecting messages/URLs the operator is authorized to inspect** (their own mail, mail reported to them, samples in an authorized phishing-analysis context).
- Every detection routine must be defensible as "read-only inspection of supplied bytes" or "metadata lookup about a domain." Nothing else.

## 3. Hard prohibitions (non-negotiable)

PhishLens MUST NOT, in any phase, under any flag:

1. **Send** anything — no email, no callbacks, no beacons, no read receipts.
2. **Dereference / fetch suspicious URLs.** Never issue an HTTP(S) request to a URL found in an analyzed message or to a URL under analysis. No HEAD, no GET, no redirect-following, no "just checking if it's alive." URLs are treated as **strings only**.
3. **Expand URL shorteners** by calling them. Shorteners are flagged, never resolved over the network.
4. **Extract, decompress, open, render, or execute attachments.** Attachment analysis is **filename + declared MIME + size + static container metadata only**. Never write attachment bytes to an executable path. Never invoke any interpreter on attachment content.
5. **Generate, store, or embed live malware, payloads, exploit code, or weaponized samples** — including in test fixtures.
6. **Build any capability that could deliver, weaponize, or operationalize** a phishing message (no template generation, no header forging helpers, no sending utilities, even "for testing").

## 4. Permitted network (only when explicitly enabled)

Default mode is **`--offline`** (no network at all). Network is opt-in via `--online` and limited to **metadata lookups about a domain**:

- DNS record retrieval: SPF (`TXT v=spf1`), DMARC (`_dmarc TXT`), DKIM selector (`<selector>._domainkey TXT`).
- RDAP lookup for domain registration/creation date (domain age).

These touch registries/resolvers about a domain. They never touch the suspicious host's content. All network code must be:
- behind the `--online` flag,
- fully mockable / injectable for tests,
- cached,
- gracefully degrading to "unknown" when offline or on failure.

## 5. Test corpus rules

- Fixtures are **synthetic and defanged**. No real malware, no real phishing payloads, no live malicious URLs.
- Suspicious domains in fixtures use reserved/example space: `example.com`, `example.org`, `*.test`, `*.invalid`, or obviously fake brand-lookalikes under `.test`.
- "Dangerous attachment" fixtures are **named** dangerously (e.g. `invoice.pdf.exe`) but contain **harmless stub bytes** (zero-byte or a short ASCII marker). Never a real binary.
- Fixtures are committed with a header comment marking them synthetic.

## 6. Engineering constraints

- Python 3.11+. Standard library `email` for parsing.
- Sync only. `httpx` (sync) for RDAP, `dnspython` for DNS. These two are the **only** runtime third-party deps.
- Dataclasses for all models. `argparse` for CLI.
- No Docker. No PyPI publish. No async. No ML.
- Determinism: identical input → identical report. No randomness, no time-dependent verdicts except domain-age (which records the reference date in the report).
- Every verdict is an explicit `Finding` with an id, severity, and human-readable reason. No opaque scores.

## 7. Quality gates (every phase)

A phase passes only when all are green:
- `ruff check .` — clean.
- `mypy .` — clean (strict-ish; no untyped defs in `src`).
- `pytest` — all pass, including the phase's new tests.
- No prohibition in §3 violated anywhere in the diff.
- Self-report returned in the required template with a binary PASS/FAIL per criterion.

## 8. Executor protocol

- Claude Code executes one phase execution pack at a time.
- Do only what the active pack specifies. Do not pull work forward from later phases.
- If a pack instruction conflicts with this file, **this file wins** — stop and report the conflict instead of proceeding.
- Return the self-report. Do not start the next phase.
