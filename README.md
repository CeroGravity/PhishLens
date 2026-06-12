# PhishLens

Defensive, purely analytical phishing-analysis tool.

Input: a raw `.eml` file **or** a URL string.
Output: a deterministic, explainable risk report (SPF/DKIM/DMARC, header
analysis, display-name mismatch, link extraction, typosquat / domain-age
detection, attachment flags).

PhishLens **explains** why a message looks malicious. It never acts on it:
it does not send anything, never fetches or expands URLs, and never opens,
extracts, or executes attachments. See `CLAUDE.md` for full governance.

## Status

Phase 0 — skeleton only. No detection logic yet. `analyze` parses arguments
and prints a "not yet implemented" notice.

## Install (dev)

```
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage (skeleton)

```
phishlens analyze message.eml
phishlens analyze --url "http://example.test/login"
```

Default mode is `--offline`. Network metadata lookups are opt-in via
`--online`.

## Gates

```
ruff check .
mypy src
pytest -q
```
