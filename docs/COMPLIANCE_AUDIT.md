# Compliance audit: vela-privacy 0.4.0

Date: 18 October 2026. Scope: the whole repository at commit `6c499ad` (library, proxy, CLI, docs, CI, packaging).
Lens: what a compliance buyer (a bank, NBFC, insurer, hospital, law firm or SaaS company processing personal data) needs before they will put Vela between their staff and an LLM, and what it would take to sell Vela as a compliance product rather than a developer library.

Regulatory references are for orientation and should be confirmed with counsel before they appear in sales material.

## Status (updated for 0.5.0)

| # | Finding | Status |
|---|---|---|
| F1 | Proxy passthrough fail-open | **Fixed in 0.4.1.** `classifyRoute()` masks or blocks every route; SDK wrappers are allowlists; residual masking pass |
| F2 | Fetch interceptor sent unreadable bodies | **Fixed in 0.4.1.** Every body type is read; invalid JSON throws |
| F3 | No audit evidence | **Fixed in 0.5.0.** Value-free, hash-chained audit events on every surface; fail closed before forwarding |
| F4 | No policy layer | **Fixed in 0.5.0.** JSON/YAML policies, presets, allowlists, `block`/`redact`/`allow` |
| F5 | Tool-call restoration | **Fixed in 0.5.0.** `restore.toolArguments: 'placeholders'`, restore report |
| F6 | Thin detection evidence | **Improved.** About 2,400-entity synthetic corpus with confidence intervals (`docs/DETECTION_REPORT.md`). An independent, human-labelled benchmark is still open |
| F7 | Checksum-valid ciphertext | **Fixed in 0.5.0.** `fpe-synthetic` action |
| F8 | Proxy hardening | **Fixed in 0.5.0.** Client tokens, tenants, rate limits, TLS, loopback-only without auth |
| F9 | Key management | **Fixed in 0.5.0.** KMS/Vault `KeyProvider` adapters. FIPS is documented, not tested in CI |
| F10 | Coverage gaps | **Improved.** Detector packs (pci, india-bfsi, health-in, us, eu-uk, intl); `nonText: block`. OCR for images is open |
| F11 | Packaging | **Fixed.** Node 22+. The security contact in `package.json` is unchanged and needs a company address |

Still open: the independent security review and penetration test, a human-labelled benchmark, OCR for images, a FIPS CI job, and the commercial console (section 3.4).

---

## 1. Summary

**What is strong.** The cryptographic core is better engineered than most products in this category: in-house NIST FF1 checked against the official vectors, fail-closed fallback to placeholders, per-session tweaks, streaming restoration, property tests, a ReDoS guard and a single runtime dependency. Vela also **stores nothing**: replacement maps live in memory for one request and are discarded. That is a strong data-minimisation story that the docs don't currently sell.

**What blocks compliance adoption today.**

| # | Finding | Severity |
|---|---|---|
| F1 | The proxy forwards **unrecognised routes unmasked by default**. Anthropic `count_tokens` and Message Batches, OpenAI legacy completions, Assistants thread messages and moderations all leak raw PII (reproduced below). | **Critical** |
| F2 | The fetch interceptor sends the request **unmasked** when the body is a `Blob`, `ReadableStream`, `FormData` or invalid JSON. | **High** |
| F3 | No audit trail. Nothing records *what was masked, blocked or restored, under which policy*. A compliance team cannot show a regulator or auditor that the control worked. | **High** |
| F4 | No policy layer: masking is the only action. There is no "block", "irreversible redact", "allow", provider/model allowlist or per-tenant policy. | **High** |
| F5 | Restored placeholders can exfiltrate data through **tool-call arguments** (documented in the threat model, not mitigated). | **High** for agentic use |
| F6 | Detection evidence is too thin to claim: the labelled corpus has **80 lines** (17 name cases). "100% recall" on that base is not a defensible statistic. | **High** (claims risk) |
| F7 | FPE output for Aadhaar, PAN and cards is **checksum-valid and indistinguishable from a real identifier**, so it may be a real third party's number. | **Medium** (design/legal) |
| F8 | The proxy has no authentication, TLS, rate limiting or tenant separation; `--api-key` on a non-loopback host is an open relay to your provider account. | **Medium** |
| F9 | No KMS/HSM integration, key IDs or rotation; no statement on FIPS mode. | **Medium** |
| F10 | Coverage gaps for regulated data: card expiry/CVV, health identifiers, Indian BFSI identifiers, non-Indian national IDs; images, audio and files pass through. | **Medium** |
| F11 | Supported runtimes include end-of-life Node 18 and Node 20. | **Low** |

---

## 2. Findings in detail

### F1. Proxy passthrough is fail-open (Critical)

`src/integrations/proxy.ts` forwards every request that `detectApiFormat()` doesn't recognise, and `passthrough` defaults to `true`. `detectApiFormat()` only matches paths that *end* in `/chat/completions`, `/responses` or `/messages`, so sub-routes and other text endpoints bypass masking. Reproduced against a local mock upstream (PII: `Rahul Sharma, PAN ABCDE1234F, rahul@company.com`):

```
masked  POST /v1/messages               [PERSON_1], PAN BOEDN3482Y, [EMAIL_1]
LEAK    POST /v1/messages/count_tokens  Rahul Sharma, PAN ABCDE1234F, rahul@company.com
LEAK    POST /v1/messages/batches       Rahul Sharma, PAN ABCDE1234F, …
LEAK    POST /v1/completions            Rahul Sharma, PAN ABCDE1234F, …
LEAK    POST /v1/threads/t1/messages    Rahul Sharma, PAN ABCDE1234F, …
LEAK    POST /v1/moderations            Rahul Sharma, PAN ABCDE1234F, …
```

`count_tokens` matters most: Anthropic SDKs and coding agents call it routinely, often just before the masked `/messages` call, so the same prompt goes out once masked and once in clear text. The README says "Every other route … is forwarded to the upstream untouched", but a compliance user reads "privacy proxy" as "nothing leaves unmasked".

**Fix:**
1. Flip the default: any `POST`/`PUT`/`PATCH` with a body on an unrecognised route is **rejected** (HTTP 403, with a clear error naming the route). Keep an explicit allowlist of body-free or known-safe routes (`GET /v1/models`) and an opt-in `--passthrough` for operators who accept the risk.
2. Mask the routes users actually need: `count_tokens` (same schema as `/messages`), Message Batches and OpenAI Batch (JSONL files) or block them, `/completions` (`prompt`), `/moderations` (`input`), Assistants thread messages.
3. Add a regression test that enumerates the public route lists of each provider and asserts every body-carrying route is either masked or rejected.

### F2. Fetch interceptor falls back to the unmasked request (High)

`src/integrations/fetch.ts` calls `originalFetch(input, init)` when the body is not a string or `Uint8Array`, or doesn't parse as JSON. A `Blob` body to `/v1/chat/completions` was forwarded with the raw PAN. Read `Blob`/`ArrayBuffer`/`ReadableStream`/`URLSearchParams` bodies (or `new Request(input, init).text()`), and **throw** for an LLM route whose body can't be read or parsed, instead of sending it.

### F3. No audit evidence (High)

The logger records counts and timings and is off by default in the library. Compliance programmes need a durable, value-free record per request. Under DPDP Rule 6 "reasonable security safeguards", GDPR Article 30 and 32, SOC 2 and ISO 27001 A.8.15/A.8.16, a team has to show the control operated, not just that it exists. The CERT-In Directions (April 2022) also require entities in India to keep ICT logs for 180 days within Indian jurisdiction, which should shape where the audit sink writes.

**Add an audit event per request** (opt-in sink, JSON lines, OpenTelemetry and webhook adapters):

```json
{
  "event": "vela.request", "request_id": "…", "ts": "…", "tenant": "…", "actor": "…",
  "route": "/v1/messages", "provider": "anthropic", "model": "claude-…",
  "policy_id": "india-bfsi", "policy_hash": "sha256:…", "vela_version": "0.5.0",
  "detectors": { "builtin": "ok", "presidio": "ok|failed|skipped" },
  "entities": { "PAN": 1, "PERSON": 2, "EMAIL": 1 },
  "actions": { "fpe": 1, "token": 3, "redact": 0, "blocked": false },
  "restored": { "content": 3, "tool_arguments": 0 },
  "key_id": "kms:…", "latency_ms": 4
}
```

Never write values or hashes of values (a hash of a 12-digit Aadhaar can be brute-forced). Offer hash-chaining (each record carries the hash of the previous one) so the log is tamper-evident. Return `x-vela-request-id` and `x-vela-entities` response headers so the calling application can join its own logs.

### F4. No policy layer (High)

Compliance teams express rules as policy, not code: "never send card numbers or secrets anywhere", "health data only to the Azure India deployment", "mask names, but allow company names". Vela today has one action (mask) set by two type lists.

**Add a declarative, versioned policy file** (`vela.policy.yaml`), loadable by the CLI, the proxy and the library, whose hash appears in every audit event:

```yaml
id: india-bfsi
version: 3
defaults: { action: mask }
entities:
  CREDIT_CARD: { action: block }          # PCI: never leaves
  CARD_CVV:    { action: block }
  SECRET_KEY:  { action: block }
  AADHAAR:     { action: token }          # placeholder, not a valid-looking number (see F7)
  ORG:         { action: allow }
  DATE_OF_BIRTH: { action: redact }       # irreversible: never restored
providers:
  allow: [ "https://*.openai.azure.com", "https://bedrock-runtime.ap-south-1.amazonaws.com" ]
models:
  allow: [ "gpt-4.1*", "claude-*" ]
non_text_content: block                   # images, audio, files (see F10)
restore:
  tool_arguments: placeholders_only       # see F5
ner: { required: true, on_failure: block }
```

Ship **presets** that map to buyer vocabulary: `dpdp-baseline`, `india-bfsi` (RBI/SEBI/IRDAI regulated entities), `pci`, `hipaa-safe-harbor`, `gdpr-pseudonymise`, `legal-privilege`.

### F5. Restoration through tool calls (High for agents)

`docs/THREAT_MODEL.md` already describes a prompt-injected model placing `[EMAIL_1]` in a tool URL so the restored value leaves through the tool. Agentic use is now the main LLM use in enterprises, so ship the listed mitigations:
- a `restore` policy per field (`content`, `tool_arguments`, `thinking`), with `placeholders_only` for tool arguments as the compliance-preset default;
- a restoration report (which placeholders were restored, into which field) returned to the application and written to the audit event;
- an optional allowlist of tool names whose arguments may be restored.

### F6. Detection evidence is too thin to claim (High, claims risk)

`tests/corpus` has 80 lines: 34 structured, 17 names, 7 addresses. The README and threat model quote "100% recall" for structured identifiers and "about 77%" for names. A regulator or a buyer's model-risk team will ask about sample size and confidence intervals, and 13 labelled names cannot support a percentage.

- Grow the corpus to at least a few thousand labelled spans per family, synthetic but realistic: Indian English, Hinglish, Indic scripts, legal pleadings, KYC forms, bank statements, discharge summaries, chat transcripts. Report precision **and** recall with 95% confidence intervals, per type and per language.
- Publish a dated **detection report** with every release, plus the Presidio-enabled numbers, since that is the recommended production setup.
- Until then, change claims such as "100% recall" to "all N labelled cases detected".

### F7. Checksum-valid ciphertext can be a real person's identifier (Medium)

Aadhaar ciphertext keeps a first digit of 2–9 and a valid Verhoeff digit; cards keep the brand digit and pass Luhn; PANs keep the holder-type letter. The output is indistinguishable from a real identifier, and some outputs **will be** real identifiers of other people. Consequences:
- the provider receives what is, in law, possibly a real third party's Aadhaar, PAN or card number;
- if a masked response escapes restoration (provider-side logs, a cached response, an evaluation dataset, a downstream system not wired to Vela), real-looking identifiers get attributed to the wrong person;
- DLP tools at the customer or the provider will flag masked traffic as live card/Aadhaar data. PCI SSC tokenisation guidance recommends that tokens be distinguishable from real card numbers.

The structural validity is a real feature (models reason better with it), so keep it, but make it a choice:
- add a `syntheticSafe` mode per type: cards mapped into reserved test-BIN ranges, Aadhaar/PAN with a deliberately invalid check character, or a placeholder;
- have the compliance presets default to placeholders for cards and Aadhaar, and FPE for the rest;
- state the trade-off in the threat model.

### F8. Proxy hardening (Medium)

`runProxy` has no authentication, TLS, rate limiting or tenant model. With `--host 0.0.0.0 --api-key …` anyone who can reach the port spends your provider quota and receives restored responses. The `x-vela-session` header is caller-controlled, so any caller can choose another conversation's tweak.

Add: a bearer-token or mTLS option (`--auth-token-file`), per-client keys mapped to tenants and policies, rate limits, TLS termination or documented sidecar patterns, and refuse to start on a non-loopback host without authentication unless `--insecure` is passed. Bind sessions to the authenticated tenant (derive the tweak from tenant plus session id).

### F9. Key management (Medium)

The FF1 key is raw bytes from a flag or `VELA_FPE_KEY`. Banks will ask for KMS or HSM custody, key IDs, rotation and separation of duties.
- Add a `KeyProvider` interface with AWS KMS, Azure Key Vault, GCP KMS and HashiCorp Vault adapters (envelope decryption at start-up); put `key_id` in audit events; support rotation by key version.
- Document FIPS: FF1 uses `node:crypto` AES, so it runs on the OpenSSL FIPS provider when Node is started in FIPS mode. ML-KEM comes from `@noble/post-quantum`, which is not a FIPS-validated module, so mark `QuantumKeyManager` as non-FIPS. Add a CI job that runs the suite with `--enable-fips`.
- Keep the post-quantum feature, but lead with KMS. Buyers ask about KMS first.

### F10. Coverage gaps for regulated data (Medium)

| Regime | Missing |
|---|---|
| PCI DSS v4.0 | Card **expiry** and **CVV/CVC** (sensitive authentication data must never be stored; sending it to an LLM provider means a third party stores it), cardholder name next to a PAN, track data |
| India BFSI and KYC | CKYC identifier, UAN/EPF, demat BO ID, CIN, DIN, TAN, LEI, MICR, SWIFT/BIC, vehicle registration, loan/policy/claim numbers (as configurable patterns), ration card |
| India health | ABHA number and address, hospital MRN/UHID |
| HIPAA Safe Harbor (18 identifiers) | All dates except year (only DOB after a cue today), ages over 89, MRN, health-plan and account numbers, certificate/licence numbers, vehicle and device IDs (VIN, IMEI), URLs, biometric identifiers, photos |
| GDPR and international | UK NINO and NHS number, EU national IDs (DNI/NIE, codice fiscale, Steuer-ID, NIR), Singapore NRIC/FIN, UAE Emirates ID, Brazil CPF/CNPJ, Canada SIN, Australia TFN/Medicare, US ITIN/EIN, ABA routing, Medicare MBI |
| Special categories (GDPR Art. 9; sensitive data under sector rules) | Health conditions, religion, caste, political opinion, sexual orientation. These are semantic, so the NER/classifier path should flag them and the policy should decide (block, warn or allow) |
| Non-text content | Images, audio and file attachments pass through (threat model non-guarantee 7). Add `non_text_content: block | allow | ocr`, with an OCR adapter as an optional async recognizer |

Ship these as opt-in **detector packs** (`vela-privacy/packs/pci`, `…/india-bfsi`, `…/hipaa`, `…/eu`) so the core stays small and precise.

### F11. Packaging and supply chain (Low)

- `engines: ">=18"` and the CI matrix include Node 18 (end of life April 2025) and Node 20 (end of life April 2026). Vulnerability scanners at regulated buyers flag EOL runtimes. Move to `>=22` in the next minor release.
- Add a CycloneDX SBOM to each release. npm provenance is already in place; also sign the container image when there is one.
- `package.json` lists a personal Gmail address as the author contact. Use a company security contact (for example `security@dharmabot.ai`) in `package.json` and `SECURITY.md`.
- The single runtime dependency is a real selling point. Keep it that way: put KMS SDKs, OpenTelemetry and OCR in optional peer packages.

---

## 3. Product recommendations for the compliance market

### 3.1 Reposition: from "privacy gateway" to "AI data-protection control with evidence"

Compliance buyers don't buy masking; they buy **a control they can show to an auditor**. The pitch should be:

> Personal data and secrets are removed before any prompt leaves your network, original values and replacement maps are never stored, every request leaves a value-free audit record (metadata only, kept by the audit sink you configure), and the policy is a versioned file your DPO signs off.

Lead with: no retention of personal data (only value-free audit metadata is kept), fail-closed by default, India-first identifiers, a mapping to the regulations, and audit evidence. Mention FF1 and post-quantum key exchange as supporting detail.

### 3.2 A regulatory mapping document (`docs/REGULATORY_MAPPING.md`)

A table of control → obligation → how Vela meets it → what the customer still owns. Candidates (have counsel confirm each row):

- **DPDP Act 2023 and DPDP Rules 2025:** reasonable security safeguards (s. 8(5) and the Rules' safeguard list, including masking and encryption); obligations for data processors under contract (s. 8(2)); cross-border transfer (s. 16); breach intimation (masking reduces what a provider-side breach exposes).
- **GDPR:** pseudonymisation under Art. 4(5), 25 and 32; EDPB Guidelines 01/2025 on pseudonymisation; the CJEU's September 2025 judgment in *EDPS v SRB* (C‑413/23 P) on when pseudonymised data is personal data for a recipient that cannot re-identify it, which matters for how a provider's role is analysed.
- **RBI:** IT outsourcing and IT governance directions, and the FREE-AI framework (August 2025). **SEBI:** CSCRF. **IRDAI:** information and cyber security guidelines.
- **PCI DSS v4.0:** Requirement 3 (rendering PAN unreadable; FPE with a managed key counts as strong cryptography, which brings key management under 3.6 and 3.7 into scope).
- **HIPAA:** Vela is a safeguard, **not** de-identification (it is reversible and coverage is partial). Say so plainly.
- **EU AI Act** data-governance duties for high-risk systems, and **ISO/IEC 27001, 27701 and 42001** control references.

### 3.3 Deployment shape that compliance teams accept

- Official container image and Helm chart, with a read-only filesystem, non-root user, `/healthz`, `/readyz` (NER reachable, key loaded, policy valid) and Prometheus `/metrics` (requests, entities by type, blocks, NER failures, latency).
- Reference deployments: sidecar next to the application, central gateway with SSO, and "Presidio or IndicNER in the same pod".
- Provider coverage enterprises in India actually use: Azure OpenAI (works through the path match, needs a test), **AWS Bedrock** (Converse and InvokeModel; requires SigV4 re-signing after masking), **Google Vertex/Gemini** (`generateContent`), and OpenAI-compatible self-hosted endpoints (vLLM, Ollama).
- A data-residency check: refuse upstreams outside the policy's allowed regions.

### 3.4 A compliance-officer surface (commercial tier)

The library stays MIT. A hosted or self-hosted **console** sells:
- dashboards of entities detected and blocked by type, team and application over time;
- a policy editor with review and approval (four-eyes) and version history;
- evidence export for audits and DPIAs ("in Q3, 1.2M requests; 0 unmasked sends; 38 NER outages, all blocked");
- alerts on spikes (a team suddenly pasting card numbers) and on NER outages;
- SSO/SCIM and role-based access, with the console itself never seeing values.

### 3.5 Assurance that buyers will ask for

1. The independent security review already planned in `SECURITY.md`, published with its summary. This is the single biggest credibility step.
2. A penetration test of the proxy.
3. A public, versioned detection benchmark (F6).
4. SOC 2 Type II or ISO 27001 for the commercial offering.
5. A DPIA template and a vendor security questionnaire pack (CAIQ/SIG Lite answers) in the repo or on the website.

---

## 4. Suggested roadmap

| Release | Scope |
|---|---|
| **0.4.1** (patch, now) | F1: fail-closed passthrough default, mask `count_tokens`, block or mask batches, legacy completions and moderations; F2: fetch-interceptor bodies; route-coverage regression test; README claim wording (F6); security contact (F11) |
| **0.5** | Audit events and request IDs (F3); policy file with block/redact/allow and presets (F4); tool-argument restore policy and restoration report (F5); proxy auth and rate limits (F8); Node ≥ 22 |
| **0.6** | KMS `KeyProvider` and FIPS CI job (F9); `syntheticSafe` FPE (F7); detector packs PCI, India BFSI and HIPAA (F10); non-text content policy; Bedrock and Gemini adapters |
| **1.0** | Independent security review published; detection benchmark of several thousand spans with confidence intervals; container image, Helm chart and metrics; regulatory mapping document |
| Commercial | Console, evidence export, SSO, hosted Presidio/IndicNER, compliance attestations |

---

## Appendix: reproducing F1 and F2

Run from the repository root with `npx tsx repro.mts` (save as an `.mts` file so top-level `await` works):

```ts
import { createServer } from 'node:http';
import { Vela } from './src/core/vela.ts';
import { runProxy } from './src/integrations/proxy.ts';
import { createFetchInterceptor } from './src/integrations/fetch.ts';

const seen: string[] = [];
const up = createServer((req, res) => {
  let b = '';
  req.on('data', (c) => (b += c));
  req.on('end', () => {
    seen.push(`${req.method} ${req.url} :: ${b}`);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
});
await new Promise<void>((r) => up.listen(9911, '127.0.0.1', () => r()));
const proxy = runProxy(new Vela(), { port: 9912, upstream: 'http://127.0.0.1:9911' });
await new Promise((r) => setTimeout(r, 200));

const pii = 'Rahul Sharma, PAN ABCDE1234F, rahul@company.com';
const chat = JSON.stringify({ model: 'x', messages: [{ role: 'user', content: pii }] });
for (const path of ['/v1/messages', '/v1/messages/count_tokens', '/v1/completions']) {
  const body = path === '/v1/completions' ? JSON.stringify({ model: 'x', prompt: pii }) : chat;
  await fetch('http://127.0.0.1:9912' + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
}
await createFetchInterceptor(new Vela())('http://127.0.0.1:9911/v1/chat/completions', {
  method: 'POST',
  body: new Blob([chat]),
});

for (const s of seen) console.log((s.includes('ABCDE1234F') ? 'LEAK   ' : 'masked ') + s);
proxy.close();
up.close();
```
