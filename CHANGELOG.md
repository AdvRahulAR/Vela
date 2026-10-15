# Changelog

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
