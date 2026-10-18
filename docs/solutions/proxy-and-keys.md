# Proxy access, tenants and keys (F8, F9)

**Symptom.**
- `--host 0.0.0.0 --api-key …` made the proxy an open relay to the operator's provider account.
- Any caller could pick another conversation's `x-vela-session` and reproduce its ciphertexts.
- The FPE key could only come from a flag or an environment variable.

**Fix.**
- `authTokens`: tenants, constant-time comparison, and the token header stripped before forwarding.
- The proxy refuses to start on a non-loopback host without tokens, unless `insecure` is set.
- Rate limits and HTTPS.
- Session ids are bound to the tenant (`sessionOptions` in `gateway.ts`).
- `KeyProvider` adapters, duck-typed so the core keeps its dependency count, and `Vela.create`.

**Invariant.** Exposure is opt-in. A configuration that reaches beyond loopback must say how clients are authenticated.

**Guarding tests.** `tests/proxy-auth.test.ts` and `tests/keys.test.ts`.
