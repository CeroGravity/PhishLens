# PhishLens test fixtures — SYNTHETIC & DEFANGED

All `.eml` files in this directory are **hand-authored synthetic samples**.
They obey `CLAUDE.md` §5:

- No real malware, no real phishing payloads, no live malicious URLs.
- All domains use reserved/example space: `example.com`, `*.test`, `*.invalid`,
  or obvious fake brand-lookalikes under `.test`.
- "Dangerous attachment" fixtures are **named** dangerously but contain only
  harmless ASCII stub bytes — never a real binary.
- Each `.eml` begins with a comment line marking it synthetic.
