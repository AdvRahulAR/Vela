# Unmasked routes and bodies (F1, F2)

**Symptom.** `POST /v1/messages/count_tokens` through the proxy reached Anthropic with every name, PAN and email in clear text. So did Message Batches, legacy `/v1/completions`, `/v1/moderations` and Assistants thread messages. The fetch interceptor sent a `Blob` or `ReadableStream` body to `/v1/chat/completions` unmasked. The SDK wrappers only replaced `create`, so `messages.countTokens`, `messages.stream()` and `batches.create` went straight to the provider.

**Root cause.** Every surface decided "is this an LLM request?" with an allowlist of three path suffixes and treated the answer *no* as *safe to forward*. The fallback branches (`forwardPassthrough`, `originalFetch`, inherited SDK methods) were written for convenience, and nothing tested them with personal data.

**Fix.**
- `classifyRoute()` in `src/integrations/formats.ts` sorts each request into `llm`, `fields` (masked top-level `input` / `prompt`), `safe` (body-free method) or `blocked`.
- The proxy and the fetch interceptor (on provider hosts) reject `blocked` with `VelaRouteBlockedError` (HTTP 403). The fetch interceptor reads every body type and throws on invalid JSON.
- The SDK wrappers use `overrideMethod` / `blockMethods` (`src/integrations/wrap-util.ts`) to mask every text method and make the rest throw.

**Invariant.** Not knowing how to mask something means blocking it (CLAUDE.md, invariant 1). One function owns route decisions (invariant 2).

**Guarding tests.** `tests/route-matrix.test.ts`: masked and blocked route lists for the proxy, every body type for the fetch interceptor, and method lists for both SDK wrappers. All use the leak oracle.

**How it was found.** By sending synthetic PII to a recording upstream through every surface (the leak oracle), not by reading code. Do that for every new surface.
