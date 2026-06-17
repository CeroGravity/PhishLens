# PhishLens

Defensive, purely analytical phishing-analysis tool.

Input: a raw `.eml` file **or** a URL string.
Output: a deterministic, explainable risk report covering SPF/DKIM/DMARC
results, header analysis, display-name / brand spoofing, link extraction,
typosquat / domain-age detection, and attachment flags.

PhishLens **explains** why a message looks malicious. It never acts on it:
it does not send anything, never fetches or expands URLs found in or under
analysis, and never opens, extracts, or executes attachments. See
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full security model.

## Authorization

Use PhishLens only on messages/URLs you are authorized to inspect — your own
mail, mail reported to you, or samples in an authorized phishing-analysis
context. It performs no offensive action and contacts no target host.

## Install (local, no PyPI)

```
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

This installs the `phishlens` console command. PhishLens is **not** published
to PyPI.

## Usage

Analyze an email file (offline by default):

```
phishlens analyze message.eml
phishlens analyze message.eml --format json
```

Analyze a URL string (treated as a string only — never fetched):

```
phishlens analyze --url "http://login.secure-example-bank.test/verify"
```

### Offline vs online

Default is `--offline`: no network at all. `--online` enables **metadata-only**
lookups about a domain — RDAP registration date (domain age) and DKIM
public-key DNS for cryptographic re-verification. It never contacts the
suspicious host or any URL in the message.

```
phishlens analyze message.eml --online
```

### Format

`--format markdown` (default) or `--format json`.

### Custom brand list

By default PhishLens uses a shipped brand list for typosquat / brand-spoof
detection. Supply your own with `--brands`:

```
phishlens analyze message.eml --brands my_brands.json
```

`my_brands.json` is a JSON array:

```json
[
  {"name": "examplebank", "aliases": ["example bank"], "domains": ["examplebank.com"]}
]
```

A malformed brand file is a usage error (exit code 2).

### Exit codes

- `0` — analysis succeeded (regardless of risk level).
- `2` — usage error (bad arguments, missing/duplicate target, bad brand file,
  file not found).
- `1` — unexpected internal error.

## Sample report

```
# PhishLens Report

- **Target:** invoice.eml
- **Mode:** eml
- **Risk category:** CRITICAL
- **Score:** 25
- **Generated at:** 2026-06-17T00:00:00+00:00

- **Auth:** spf=softfail dkim=none dmarc=none aligned=None

## Findings

| Severity | ID | Reason | Evidence |
| --- | --- | --- | --- |
| HIGH | ATTACH.DANGEROUS_EXTENSION | The attachment's final extension is an executable or script type. | filename=invoice.pdf.exe ext=.exe |
| HIGH | ATTACH.DOUBLE_EXTENSION | The filename hides its real type behind a document/media extension. | filename=invoice.pdf.exe extensions=('pdf', 'exe') |
| MEDIUM | AUTH.SPF_FAIL | The receiving server reported an SPF failure/softfail. | spf=softfail |
| LOW | HDR.MISSING_MESSAGE_ID | The message has no Message-ID header. | |
```

## Determinism

Identical input yields an identical report. The only clock read is the report's
`generated_at` timestamp; domain-age findings record their reference date in
the evidence. Scoring is transparent weighted addition with documented
severity weights and category thresholds.

## Development

```
ruff check .
mypy .
pytest -q
```
