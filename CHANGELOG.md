# Changelog

## 0.4.1

**Security fix: unmasked requests through unrecognised routes.** Found by the compliance audit (`docs/COMPLIANCE_AUDIT.md`, F1 and F2). Upgrade if you use the proxy, the fetch interceptor or a client wrapper.

- **Proxy:** routes Vela didn't recognise were forwarded with their text unmasked, including Anthropic `/v1/messages/count_tokens` and Message Batches, OpenAI legacy `/v1/completions`, `/v1/moderations` and Assistants thread messages. Now:
  - `count_tokens` and `/v1/responses/input_tokens` are masked like the requests they count;
  - `/completions` prompts and `/moderations` input are masked (streaming legacy completions is rejected);
  - any other route that carries a body is **rejected with HTTP 403** (`VelaRouteBlockedError`) and nothing is sent.
  - Body-free requests (`GET /v1/models`) still pass. The new `passthrough` modes are `'safe'` (default), `'none'` and `'all'`. `'all'` (or `true`) restores the old behaviour as an explicit opt-in. CLI: `--passthrough safe|none|all`.
- **Fetch interceptor:** a request body that wasn't a string or `Uint8Array` (a `Blob`, `ArrayBuffer`, `ReadableStream`…) was sent unmasked. Every body type is now read and masked. An LLM request whose body isn't valid JSON throws instead of being sent. On known provider hosts, the route rules above apply (`passthrough: 'all'` opts out).
- **Client wrappers:** methods other than `create` went to the provider unmasked.
  - Now masked:
    - OpenAI `chat.completions.parse`, `responses.parse`, `responses.inputTokens.count`, `completions.create`, `embeddings.create` and `moderations.create`;
    - Anthropic `messages.countTokens` and `beta.messages.create`/`countTokens`.
  - Now throw `VelaRouteBlockedError`: methods Vela can't mask (`stream()` helpers, batches, file uploads, audio, image generation, Assistants threads).
- New exports: `classifyRoute`, `maskFieldsAsync`, `forwardFieldsRequest`, `VelaRouteBlockedError`.
- Docs: corpus results are stated as counts, not recall percentages; threat model and reviewer guide updated (new fail-open checklist).

## 0.4.0

NER services as a first-class, fail-closed detection path.

- **Async recognizers:** new `asyncRecognizers` option for batched, asynchronous recognizers such as an NER service. They run once per request before masking. Spans use JavaScript string offsets and are merged with built-in detection; unknown types are always masked.
- **Presidio adapter:** `presidioRecognizer({ url })` calls a Microsoft Presidio Analyzer and converts its code-point offsets to JavaScript offsets (emoji and other astral characters no longer shift spans). Example setup in `examples/presidio/`. CLI: `vela proxy --presidio-url <url>` (add `--presidio-optional` to fall back instead of blocking) and `vela mask --presidio-url <url>`.
- **Fail closed:** `recognizerFailure: 'block'` (default) rejects the request with `VelaRecognizerError` if a recognizer fails or exceeds `recognizerTimeoutMs` (default 5000). The proxy and Express middleware return HTTP 503 and send nothing upstream. `'continue'` falls back to built-in detection and logs a warning.
- **New async API:** `vela.maskAsync()`, `session.prepare()` / `session.prepareValue()`, `maskLlmRequestAsync()`, `maskOpenAiRequestAsync()`, `maskOpenAiResponsesRequestAsync()`, `maskAnthropicRequestAsync()`. The proxy, fetch interceptor, Express middleware and both client wrappers use the async path automatically, with no behaviour or latency change when no async recognizers are configured.
- **Breaking (only with `asyncRecognizers` set):** synchronous `vela.mask()`, `session.mask()` and the sync request helpers throw `VelaNotPreparedError` for text that hasn't been prepared, so text can't skip NER by accident. Without `asyncRecognizers` nothing changes.
- **Performance fix:** detection was super-linear on large inputs (overlap resolution, re-mention and citation checks compared every entity with every other). It now uses sorted interval lookups and scales linearly: a 400 KB prompt is about 7× faster, and the gap grows with size. Found by the new performance test.
- Docs: README "Project status" section, threat model, security reviewer guide and `SECURITY.md`.

### Reliability (CI, deeper tests and the fixes they found)

- **Fix:** in `maskValue`, a placeholder-shaped literal in a later field (e.g. `[EMAIL_3]`) could collide with a placeholder issued for an earlier field, so restoration turned the literal into a real value. All leaves are now scanned before masking. Found by the new property-based tests.
- **Fix:** all-lowercase names at the end of a sentence ("I met deepa.") were missed.
- **Fix:** lowercase gazetteer names in code and file paths (`import emma from './emma.ts'`, `rahul_sharma.log`) are no longer tagged as people.
- **Fix:** labelled addresses no longer stop at abbreviations such as "No." ("House No. 14, Sector 21…" was split and "14" leaked).
- New `maxInputChars` option (default 2,000,000): a larger single text throws `VelaInputTooLargeError`; the proxy and Express middleware return HTTP 413 without forwarding. New exported `VelaError` base class; the proxy and middleware return its `status`.
- Releases are now published from GitHub Actions with npm provenance, after tests pass on Node 18, 20, 22, 24 and Windows. A packed-install smoke test checks `require`, `import` and the CLI on every Node version.
- New test suites: property-based tests (round-trip, no leakage, checksum validity, streaming, JSON, determinism), a labelled detection corpus with a recall/false-positive gate (`npm run eval`), and a ReDoS / performance guard for every detector regex.

## 0.3.2

Fixes for the gaps found by an external test of 0.3.1.

- **Fix:** entities with a custom type (from `customDetectors` or `recognizers`, e.g. `EMP_ID`) were passed through unmasked unless the type was also listed in `tokenTypes`. Any non-built-in type is now always masked (placeholder, or FPE if listed in `fpeTypes`). `fpeTypes` / `tokenTypes` keep their opt-out semantics for built-in types and are now documented as replacing the defaults.
- All-lowercase names are detected (`rahul sharma called. arjun told deepa…`), including lowercase re-mentions of a known name (`sharma`). Gazetteer names that are ordinary English/Hindi words in lowercase (`harsh`, `christian`, `vikas`, `deepak`…) are only matched when capitalised or after a cue.
- A partial mention of a person (`Joseph`, `Mr. Sharma`, `SHARMA`) now gets the same placeholder as the full name seen in the session and is restored as the full name. Case variants share one placeholder. Ambiguous short mentions (two known people called Rahul) still get their own placeholder. Opt out per session with `linkPartialNames: false`. Placeholder numbers for people are no longer guaranteed to follow text order.
- Party names inside reported court citations (`… v. … (2019) 3 SCC 123`, `AIR 2020 Ker 55`, `2021 SCC OnLine Ker 99`, `in X v. Y (supra)`) are left intact, as the README promised. `maskCitationParties: true` masks them.
- Emails containing combining marks (Devanagari and similar scripts, e.g. `राहुल@उदाहरण.भारत`) are detected.
- Version strings (`v1.2.3.4`, `version 1.2.3.4`, `upgraded to 2.0.1.3`) are no longer masked as IP addresses.
- New detections: `password=` / `api_key:` / `token=` style credentials (also in JSON fields), AWS secret access keys, and `MAC_ADDRESS` (colon, dash and Cisco dot formats; placeholder).
- **Fix:** `require('vela-privacy')` crashed on Node versions without `require(esm)` support (18, 20 before 20.19, 22 before 22.12) because the ESM-only `@noble/*` packages were loaded with `require`. They are now bundled into the CommonJS build and CLI. ML-KEM key generation and encapsulation take randomness from `node:crypto`, so they also work on Node 18, which has no global `crypto`.

## 0.3.1

- Detect Slack app-level tokens (`xapp-…`).
- Mask PII in tool/function definitions (descriptions, `input_schema` / `parameters`) for OpenAI Chat, OpenAI Responses and Anthropic.
- Placeholder-shaped text already in the input (e.g. a literal `[EMAIL_1]`) is reserved, so it can no longer collide with a real placeholder on restore.
- Proxy forwards non-chat routes (`/v1/models`, …) instead of returning 404; `/v1/embeddings` input is masked. `--no-passthrough` restores strict 404s.
- New detectors: `VOTER_ID` (context-gated) and `DRIVING_LICENCE`, masked as placeholders.
- README: clarified that detection is heuristic; documented proxy routes.

## 0.3.0

### Security / correctness
- Replaced `ff1-js` (fails the NIST FF1 test vectors) with an in-house NIST SP 800-38G FF1, verified against all 9 official samples.
- Structure-aware FPE: Aadhaar (Verhoeff), cards (Luhn, brand kept), PAN (holder type kept), GSTIN (check char, consistent with PAN), IBAN (mod-97), phones (country code kept), SSN (valid ranges), IPv4 (valid octets), bank account, passport, IFSC.
- Fail-closed: values whose domain is below the NIST 10^6 minimum, or that can't be format-preserved, become placeholders instead of passing through in plaintext.
- Per-session, per-type FF1 tweaks (no cross-session linkability); optional stable `sessionId`.
- Multi-message requests are masked in one session, so placeholders are unique across messages (fixes wrong restoration).
- Proxy binds to 127.0.0.1 by default; request bodies are read as bytes (fixes UTF-8 corruption).
- Key sealing uses a dedicated HKDF-derived key and supports AAD.

### Providers
- Anthropic Messages: `system`, content blocks, `tool_use.input`, `tool_result`, documents; JSON and SSE restore; `x-api-key` / `anthropic-version` handling; auto-routing to api.anthropic.com.
- OpenAI Responses API: request masking (previously crashed) and JSON/SSE restore.
- Streaming: separate lanes per choice, per tool call and per content block; held-back text is flushed at `finish_reason` / `content_block_stop`; tool-call arguments restored in streams.
- `wrapOpenAiClient` also wraps `responses.create`; new `wrapAnthropicClient`; SDK `Stream` helpers keep working.
- Fetch interceptor supports `Request` objects and exact host matching; Express middleware forwards query strings and headers.

### Detection
- Removed CASE_ID.
- Added: person names (heuristic plus pluggable `recognizers`), addresses, date of birth, passport, bank account, IFSC, UPI ID, PIN/ZIP, organisations, IPv6, international and North American phones, spaced IBANs, lowercase PANs, internationalised emails, more secret formats.
- Fewer false positives: bare 10-digit numbers after order/invoice/ref… are no longer treated as phones.

### Restoration
- JSON-safe placeholders `[TYPE_n]`; values restored into JSON strings are escaped.
- Tolerates reformatting by the LLM (separators, case, missing brackets).

### CLI
- Fixed argument parsing; `--host`, `--api-key`, `--json`, `--version`; `keygen` prints a full key, and `keygen --kem` prints a full ML-KEM keypair.
