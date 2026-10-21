# Review of the provider and operations work

Tests: `tests/review-providers.test.ts`.

| Gap | Root cause | Fix |
|---|---|---|
| Vertex AI's global host (`aiplatform.googleapis.com`) passed the fetch interceptor unmasked | The host list had only the regional `-aiplatform` suffix | The global host is a provider host |
| Gemini `thought: true` parts were restored despite `thinking: 'placeholders'` (JSON responses) | Field kinds came from key names; Gemini marks reasoning with a flag | `unmaskValue` treats `thought: true` objects as thinking |
| An operator's OpenAI key could be sent to Google or Anthropic | One `apiKey` was injected into every auto-routed provider | `selectApiKey`: per-provider `apiKeys`; never send a key to another provider |
| The Gemini model allowlist read `body.model` (spoofable, normally absent) | Gemini puts the model in the URL | `modelOf()` prefers the path |
| Bedrock image and document bytes were turned into plain objects; text documents went unmasked | The residual pass walked `Uint8Array` like an object | Binary passes through; `txt`/`md`/`csv`/`html` documents are decoded, masked and re-encoded |
| Unauthenticated `/readyz` could flood the NER service; `/metrics` exposed tenant names | Ops endpoints skip auth | `/readyz` is cached; tenant labels are opt-in |

**Lesson:** when you add a provider, add its hosts, model location, key routing, reasoning markers and binary fields to the route matrix and the review checklist, not just its request walker.
