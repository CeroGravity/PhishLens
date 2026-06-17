# DKIM test keys — TEST-ONLY, THROWAWAY

`test_private.pem` / `test_public_b64.txt` are a **disposable RSA-1024 keypair
generated solely for the offline DKIM verification tests**. They sign synthetic
`.test` messages in the test suite, with the public key served via an injected
`dnsfunc` (no real DNS).

- NOT a production key. Never used outside `tests/`.
- Committing the private key is intentional and harmless: it protects nothing.
- Lets the DKIM tests run fully offline with no `openssl` dependency at test time.
