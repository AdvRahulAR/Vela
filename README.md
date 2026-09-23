# Vela — Universal LLM Privacy Gateway

<p align="center">
  <strong>Quantum-resilient PII masking & format-preserving anonymization for any LLM, app, or agent. Built by Dharmabot AI.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/vela-privacy"><img src="https://img.shields.io/npm/v/vela-privacy.svg?style=flat-square&color=blue" alt="npm version" /></a>
  <a href="https://github.com/AdvRahulAR/Vela"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="license" /></a>
  <a href="https://csrc.nist.gov/pubs/fips/203/final"><img src="https://img.shields.io/badge/post--quantum-ML--KEM--768%20(FIPS%20203)-purple.svg?style=flat-square" alt="NIST FIPS 203" /></a>
  <a href="https://csrc.nist.gov/pubs/sp/800/38/g/r1/final"><img src="https://img.shields.io/badge/encryption-FF1%20FPE%20(NIST%20SP%20800--38G)-orange.svg?style=flat-square" alt="NIST SP 800-38G" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/typescript-strict%20100%25-blue.svg?style=flat-square" alt="TypeScript Strict" /></a>
</p>

---

## Why Vela?

Most PII masking solutions break LLM reasoning by replacing structured identifiers with destructive tags like `[REDACTED]` or `<PII id="1"/>`. Downstream models lose length, character set context, and formatting expectations.

**Vela** combines **NIST SP 800-38G FF1 Format-Preserving Encryption (FPE)** with **ML-KEM-768 (NIST FIPS 203)** post-quantum key agreement. Real structured IDs become realistic encrypted tokens of identical length and charset, while soft PII is mapped to semantic reversible tokens.

| Feature | Naive Regex / Redaction | Rehydra / Presidio | Vela |
|---|:---:|:---:|:---:|
| **Structured Output** | `[REDACTED]` | `<PII type="ID" id="1"/>` | `2602 9025 6010` (Format-Preserving) |
| **Format Preserved** | ❌ No | ❌ No | ✅ **Yes** (Length, Charset, Delimiters) |
| **Reversibility** | ❌ Irreversible | Memory Map Lookup | ✅ **Keyed O(1) Memory** |
| **Quantum Resilient** | ❌ None | ❌ None | ✅ **ML-KEM-768 + AES-256-GCM** |
| **Streaming SSE** | ❌ No | ⚠️ Partial | ✅ **Chunk-Boundary Aware Buffer** |
| **Checksum Verification** | ❌ No | ⚠️ Basic | ✅ **Verhoeff (Aadhaar) + Luhn (Cards)** |
| **API Secret Leak Prevention** | ❌ No | ❌ No | ✅ **OpenAI, Anthropic, AWS, GitHub Keys** |
| **Multi-Surface** | SDK Only | SDK Only | ✅ **SDK, OpenAI, Fetch, Express, CLI** |

---

## Architecture

```
[ User Input ]
       │
       ▼
┌────────────────────────────────────────────────────────┐
│               Vela Privacy Gateway Engine               │
│                                                        │
│  1. Checksum Detection (Verhoeff, Luhn, Regex, Leaks)  │
│  2. Format-Preserving Encryption (NIST FF1)            │
│  3. Post-Quantum Key Agreement (ML-KEM-768 FIPS 203)   │
│  4. Semantic Token Replacement for Soft PII            │
└────────────────────────────────────────────────────────┘
       │ (Outbound Masked Request)
       ▼
[ External LLM Provider (OpenAI / Anthropic / Local) ]
       │ (Inbound Response / SSE Stream)
       ▼
┌────────────────────────────────────────────────────────┐
│            Vela Real-Time Stream De-Masker             │
│                                                        │
│  - Reassembles split tokens across chunk boundaries    │
│  - Restores originals using keyed session state        │
└────────────────────────────────────────────────────────┘
       │
       ▼
[ Unmasked Plaintext to Application ]
```

---

## Installation

```bash
npm install vela-privacy
```

Dual-format build supporting both **ESM** (`import`) and **CommonJS** (`require`).

---

## Quick Start

### 1. Direct Core SDK

```typescript
import { Vela, QuantumKeyManager } from 'vela-privacy';

// 1. Post-Quantum Key Agreement (ML-KEM-768)
const bob = QuantumKeyManager.generateKeyPair();
const { cipherText, sharedSecret } = QuantumKeyManager.encapsulate(bob.publicKey);
const fpeKey = QuantumKeyManager.deriveFpeKey(sharedSecret);

// 2. Initialize Vela
const vela = new Vela({
  fpeKey,
  glossary: ['ProjectApollo', 'SecretAcquisition'],
});

// 3. Mask PII in prompt
const prompt = 'User PAN ABCDE1234F, Aadhaar 2345 6789 0123, email alice@company.com works on ProjectApollo.';
const masked = vela.mask(prompt);

console.log(masked.text);
// "User PAN JKRZ2WFMOD, Aadhaar 4892 1045 7712, email <PII type="EMAIL" id="0"/> works on <PII type="CUSTOM" id="1"/>."

// 4. Restore LLM Response
const llmResponse = 'Verified tax record for PAN JKRZ2WFMOD and notified <PII type="EMAIL" id="0"/> regarding <PII type="CUSTOM" id="1"/>.';
const unmasked = vela.unmask(llmResponse, masked);

console.log(unmasked.text);
// "Verified tax record for PAN ABCDE1234F and notified alice@company.com regarding ProjectApollo."
```

---

## Integration Surfaces

### 2. OpenAI SDK Wrapper (Sync + Streaming)

Wrap your OpenAI client in one line. Outgoing prompts and tool call arguments are masked before leaving your server, and incoming responses (including streaming chunks) are unmasked in real time:

```typescript
import OpenAI from 'openai';
import { Vela, QuantumKeyManager, wrapOpenAiClient } from 'vela-privacy';

const fpeKey = QuantumKeyManager.deriveFpeKey(sharedSecret);
const vela = new Vela({ fpeKey });

const openai = wrapOpenAiClient(new OpenAI({ apiKey: process.env.OPENAI_API_KEY }), vela);

// Standard Completion
const completion = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Audit tax PAN ABCDE1234F for user@example.com' }],
});

// Streaming Completion (automatically de-masked across SSE chunk boundaries)
const stream = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Generate report for PAN ABCDE1234F' }],
  stream: true,
});

for await (const chunk of stream) {
  process.stdout.write(chunk.choices[0]?.delta?.content || '');
}
```

### 3. Global Fetch Interceptor

Zero code modifications to existing API clients. Automatically intercepts OpenAI/Anthropic endpoints:

```typescript
import { Vela, createFetchInterceptor } from 'vela-privacy';

const vela = new Vela({ fpeKey });
globalThis.fetch = createFetchInterceptor(vela);

// All subsequent calls to /v1/chat/completions are automatically masked and unmasked!
```

### 4. Express / Connect Middleware

```typescript
import express from 'express';
import { Vela, createExpressMiddleware } from 'vela-privacy';

const app = express();
app.use(express.json());

const vela = new Vela({ fpeKey });

// Proxy /v1/chat/completions upstream to OpenAI with zero-trust privacy
app.use(createExpressMiddleware(vela, {
  upstream: 'https://api.openai.com',
  apiKey: process.env.OPENAI_API_KEY,
}));

app.listen(3000);
```

### 5. Standalone Proxy Server & CLI

Launch a high-performance local privacy gateway without writing any backend code:

```bash
# Start proxy listening on port 8787
npx vela-privacy proxy --port 8787 --upstream https://api.openai.com

# Generate production ML-KEM-768 keys
npx vela-privacy keygen

# Quick CLI masking test
npx vela-privacy mask "My PAN is ABCDE1234F and email is test@domain.com"
```

Then point any client at `http://127.0.0.1:8787/v1`:

```bash
curl http://127.0.0.1:8787/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "My PAN is ABCDE1234F"}]
  }'
```

---

## Supported PII & Entity Detectors

| Entity | Validation Technique | Masking Strategy |
|---|---|:---:|
| **Aadhaar (UIDAI)** | **Verhoeff Checksum Algorithm** (rejects invalid 12-digit numbers) | **FF1 FPE** (Digits + Spacing preserved) |
| **Credit / Debit Cards** | **Luhn Algorithm (Mod 10)** (Visa, Mastercard, Amex, RuPay) | **FF1 FPE** (Digits + Delimiters preserved) |
| **PAN (Indian Tax)** | 10-char Alphanumeric format | **FF1 FPE** (Upper Alnum preserved) |
| **GSTIN** | State code check (01–38, 97, 99) + 15-char structure | **FF1 FPE** (Upper Alnum preserved) |
| **Indian Court Case IDs** | Supreme Court, High Court, District citation formats | **FF1 FPE** |
| **API Keys & Secrets** | OpenAI (`sk-...`), Anthropic (`sk-ant-...`), AWS (`AKIA...`), GitHub (`ghp_...`), Slack | **Semantic Token** |
| **JWTs** | `eyJ...` 3-segment bearer tokens | **Semantic Token** |
| **Email Addresses** | RFC-compliant email regex | **Semantic Token** |
| **Phone Numbers** | E.164 and Indian (+91) formats | **FF1 FPE** |
| **SSN (US)** | 9-digit hyphenated format | **FF1 FPE** |
| **IP Addresses** | IPv4 standard notation | **FF1 FPE** |
| **Custom Glossary** | Case-insensitive configurable dictionary / allowlists | **Semantic Token** |

---

## Benchmarks

Measured on Node.js v22 (AMD Ryzen 9 / Apple Silicon equivalent):

```
=== Vela Privacy Benchmark (1,000 iterations) ===

Masking:
  Average latency:  0.93 ms / op
  Throughput:       1,068 ops / sec

Unmasking:
  Average latency:  0.013 ms / op (13 microseconds!)
  Throughput:       76,311 ops / sec

ML-KEM-768 Handshake:
  Average latency:  2.91 ms / handshake
```

---

## Security & Cryptography Specification

1. **Post-Quantum Key Agreement**: ML-KEM-768 (NIST FIPS 203), standardized by NIST for post-quantum key encapsulation. Defeats **Harvest-Now-Decrypt-Later (HNDL)** attacks.
2. **Format-Preserving Encryption**: NIST SP 800-38G FF1 implementation. Provides cipher block protection while keeping exact length, character radix, and structural spacing.
3. **Key Derivation**: HKDF-SHA256 (RFC 5869) derives sub-keys for separate tenant spaces without storing master secrets.
4. **Key Sealing in Transit**: AES-256-GCM authenticated encryption protects exported keys across network boundaries.
5. **Zero-PII Telemetry**: Structured JSON logger records entity counts and latencies without ever persisting or leaking raw PII.

---

## License

MIT © [Dharmabot AI](https://dharmabot.ai)
