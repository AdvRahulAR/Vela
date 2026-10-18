# Security review guide

This guide is for an independent reviewer of vela-privacy. It lists the code in scope, the questions we most want answered, and how to run every test suite. Read [THREAT_MODEL.md](THREAT_MODEL.md) first: it defines the guarantees under review.

## Getting started

Requires Node 22 or newer.

```bash
git clone https://github.com/AdvRahulAR/Vela.git && cd Vela
npm ci
npm run typecheck && npm run lint
npm test                    # unit, regression, property, corpus, ReDoS/performance, async-recognizer suites
npm run coverage            # same with coverage report in coverage/
npm run smoke               # builds, packs, installs and exercises the published artifact
npm run eval                # detection precision/recall per type over tests/corpus
VELA_PBT_RUNS=5000 npm test # deeper property-based run
```

## Scope

**Core (highest priority):**

| File | Lines | What it does |
|---|---|---|
| `src/core/ff1.ts` | ~150 | NIST SP 800-38G FF1 implementation (AES-based Feistel) |
| `src/core/fpe.ts` | ~410 | Structure-aware FPE per identifier type: templates, checksum recomputation, cycle-walking, small-domain rejection, tweak derivation |
| `src/core/session.ts` | ~380 | Masking session: replacement maps, placeholder issuance and reservation, partial-name linking, async recognizer preparation, fail-closed checks |
| `src/core/matcher.ts` | ~240 | Restoration, including tolerant matching of reformatted placeholders and the streaming restorer |
| `src/core/quantum.ts` | ~130 | ML-KEM-768 key agreement, HKDF-SHA256 derivation, AES-256-GCM key sealing |

**Integrations:**

| File | Lines | What it does |
|---|---|---|
| `src/integrations/gateway.ts` | ~210 | Request masking and forwarding, response restoration, header stripping |
| `src/integrations/proxy.ts` | ~150 | HTTP proxy: body limits, routing, error mapping |
| `src/integrations/formats.ts` | ~160 | Which fields of OpenAI / Anthropic requests are masked |
| `src/core/streaming.ts` | ~380 | SSE parsing and per-choice / per-block restoration |
| `src/integrations/presidio.ts` | ~110 | NER adapter and code-point → UTF-16 offset conversion |

**Detection** (`src/core/detector.ts`, `src/core/names.ts`) is in scope for denial of service and for logic errors that cause a *detected* value to be passed through. Detection recall itself is measured by the corpus and is a known limitation, not a review target.

## Questions for the reviewer

**FF1 and FPE**

1. Is the FF1 implementation correct beyond the nine NIST sample vectors, including radix handling, numeral-string conversion and the round function for odd lengths?
2. `fpe.ts` encrypts values as mixed-radix integers with cycle-walking to keep outputs inside valid sets (Verhoeff, Luhn, IBAN mod-97, GSTIN check character, valid SSN ranges, IPv4 octets). Is the mapping a bijection on each domain, and does cycle-walking always terminate?
3. Values whose domain is below NIST's 10⁶ minimum become placeholders. Is that check applied to the *effective* domain after fixed characters (brand digits, holder-type letters, country codes) are excluded?
4. Tweaks are `SHA-256("vela-fpe-tweak-v1|" + seed + "|" + type)` truncated to 16 bytes, where `seed` is either `sid:<sessionId>` or 16 random bytes. Is the domain separation adequate? Is it acceptable that a caller-chosen `sessionId` makes ciphertexts linkable by design?

**Key handling**

5. `quantum.ts`: are HKDF labels (`vela-fpe-key-v1`, `vela-seal-key-v1`) used consistently, are AES-GCM nonces random and never reused under one key, and is AAD bound correctly?
6. Does any code path log, return or serialise the FPE key or a session map?

**Masking and restoration**

7. Can any request field that reaches the provider skip masking? `formats.ts` decides which fields are walked. Compare it against the OpenAI Chat, OpenAI Responses and Anthropic Messages request schemas.
8. With async recognizers configured, `session.prepareValue()` collects strings and `mask()` throws `VelaNotPreparedError` for anything not prepared. Is there a path where text is masked without preparation and without the error?
9. Can restoration produce an original value at a position where it was not masked from, other than by the model echoing a placeholder? See the restoration risk section of the threat model, including tool-call arguments.
10. Tolerant restoration also matches reformatted placeholders (`EMAIL_1` without brackets, changed case). Can user-controlled text that never contained a placeholder be rewritten into an original value?
11. Partial-name linking (`session.ts`, `maskEntity`) reuses a placeholder when a short mention matches exactly one known full name. Can it ever map one placeholder to two different originals?

**Proxy and denial of service**

12. Header handling: are `host`, `content-length`, hop-by-hop and authentication headers stripped or replaced correctly when forwarding, and can a client make the proxy send its configured API key to a different host?
13. Body size, `maxInputChars`, recognizer timeouts and the ReDoS suite (`tests/perf.test.ts`) aim to bound work per request. Is there an input that still causes super-linear time or unbounded memory?

## Fail-open checklist

Run through this for every change that touches an integration. Each item is a way a past version leaked (see `docs/solutions/`).

- Every branch that calls `originalFetch`, `forwardPassthrough` or `next()` with a request body: can a request on an LLM provider route reach it? It must be masked, body-free, or rejected.
- Every `catch` around parsing or masking: does it fall back to sending the original? It must throw a `VelaError` instead.
- Every new provider route or SDK method: is it in `tests/route-matrix.test.ts`, as masked or blocked?
- Every log, error message and audit field: can it contain a value? Only counts, types, routes and timings may be logged.
- Every new option: is the default the fail-closed choice, with the open choice an explicit opt-in?

## Known limitations (not findings)

These are documented in the threat model:

- Detection recall below 100% for names and addresses without NER.
- Format leakage inherent to format-preserving encryption.
- Placeholders revealing entity type and count.
- Linkability within a session.
- The tool-call restoration risk.

Findings that change their severity or make them exploitable in a new way are welcome.

## Reporting

Report findings privately as described in [SECURITY.md](../SECURITY.md). For the final report, a summary we can link from `SECURITY.md` is appreciated.
