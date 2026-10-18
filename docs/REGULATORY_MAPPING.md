# Regulatory mapping

How Vela's controls relate to obligations a regulated organisation commonly has when its staff or products send data to an LLM provider. **This is an engineering aid, not legal advice.** Confirm every row with your counsel or DPO. Regulations change, and what a control "satisfies" depends on your whole programme, not on one tool.

Each row has three columns:

- **Vela provides:** what the software does.
- **Evidence:** what you can show an auditor.
- **You still own:** what the software cannot do for you.

## Cross-cutting controls

| Control | Vela provides | Evidence | You still own |
|---|---|---|---|
| Data minimisation | Detected personal data is replaced before the request leaves; FPE keeps structure only where needed; `redact` for values the model never needs back | Policy file and hash; `actions` counts per request in the audit log | Deciding what may be sent at all; the purpose of each AI use |
| Pseudonymisation | FF1 (NIST SP 800-38G) ciphertext and placeholders; key in your KMS; mapping kept only in memory for one request | Policy, `key_id` in audit events, threat model | Key custody; whether the provider can re-identify from context |
| Fail-closed processing | Unknown routes and SDK methods, unreadable bodies, NER outages, blocked entity types and audit-log failures all stop the request | `vela.blocked` / `vela.error` events; tests in `tests/route-matrix.test.ts` | Monitoring blocks and fixing their cause |
| Accountability and logging | Value-free audit event per request, hash-chained, with policy hash, key id, tenant and model | `audit.jsonl` plus `vela audit verify --head` | Retention, write-once storage, access control on the log |
| Processor and cross-border controls | Provider and model allowlists; region pinning through `providers.allow` | Policy file; blocked events for disallowed hosts | Contracts (DPA / processor terms), transfer assessments |
| Agentic risk | Tool-call arguments keep placeholders (`restore.toolArguments`) | `restore.kept` counts in audit events | Approving which tools an agent may run |
| Security of the control | Proxy client tokens, rate limits, TLS, non-root container, no values in logs | Helm values, `SECURITY.md`, threat model | Network placement, patching, the independent review |

## India

| Obligation | Relevant Vela controls | Notes |
|---|---|---|
| **DPDP Act 2023, s. 8(5)** (reasonable security safeguards to prevent a personal data breach) and the **DPDP Rules 2025** safeguard list (encryption, obfuscation, masking, access logs, retention of logs) | Masking and FPE, audit trail, fail-closed processing, `dpdp-baseline` preset | Logs show *that* masking happened, not what was masked. Keep them for the period your Rules analysis requires. |
| **DPDP Act s. 8(2)** (engaging a data processor only under a valid contract) | Provider allowlist ensures only contracted providers are used | The contract itself is yours |
| **DPDP Act s. 16** (transfers outside India, subject to Central Government restrictions) | `providers.allow` pinned to in-region endpoints (e.g. Azure India, Bedrock `ap-south-1`) | Confirm where the provider actually processes and stores data |
| **DPDP Act s. 8(6)** (breach intimation) | Less personal data reaches the provider, so there is less to report if the provider is breached | Breach response remains yours |
| **CERT-In Directions (28 April 2022)** (ICT logs kept for 180 days within Indian jurisdiction) | `jsonlFileSink` / `--audit-stdout` to a store in India | Configure retention and location |
| **RBI** (IT outsourcing and IT governance directions; FREE-AI framework, August 2025) | Policy-as-code with approval, audit evidence, model allowlist, `india-bfsi` preset | Board-approved AI policy, model risk management, vendor due diligence |
| **SEBI** (CSCRF) and **IRDAI** (information and cyber security guidelines) | Logging, access control on the proxy, data minimisation | Map to your entity's control catalogue |
| **Aadhaar Act** restrictions on storing and displaying Aadhaar numbers | `AADHAAR: fpe-synthetic` or `token`; values never logged | Whether Aadhaar may be processed for the purpose at all |

## Europe and the UK

| Obligation | Relevant Vela controls | Notes |
|---|---|---|
| **GDPR Art. 4(5), 25, 32** (pseudonymisation, privacy by design, security of processing) | FPE and placeholders, key in KMS, `gdpr-pseudonymise` preset, `eu-uk` pack | Pseudonymised data is still personal data for you. EDPB Guidelines 01/2025 describe pseudonymisation good practice. |
| **GDPR, the recipient's view.** In *EDPS v SRB* (C‑413/23 P, 4 September 2025), the CJEU held that pseudonymised data may not be personal data for a recipient that cannot reasonably re-identify it | Per-request random tweaks, no shared maps, provider never holds the key | Context in the prompt can still identify people. Assess this per use case. |
| **GDPR Art. 30** (records of processing) | Audit events give per-request evidence of the safeguard | The record of processing activities is yours |
| **GDPR Art. 9** (special categories) | NER via Presidio; `block` for types your recognizer labels | Built-in detectors don't classify health, religion or similar *topics* |
| **EU AI Act** (data governance and logging duties for high-risk systems) | Audit trail, policy versioning | Classification of your system, conformity assessment |

## Payments and health

| Obligation | Relevant Vela controls | Notes |
|---|---|---|
| **PCI DSS v4.0 Req. 3.3** (no storage of sensitive authentication data after authorisation) | `pci` pack (CVV, track data) with `block` | Blocked before reaching the provider |
| **PCI DSS Req. 3.5** (PAN unreadable wherever stored) | `CREDIT_CARD: fpe-synthetic` (Luhn-invalid, distinguishable from a real PAN) or `block` | FPE with a managed key brings key management (3.6, 3.7) into scope. Your QSA decides scope. |
| **HIPAA Security Rule** (technical safeguards) | Masking, audit, `hipaa-safe-harbor` preset | Vela is **not** de-identification under §164.514: masking is reversible and coverage of the 18 identifiers is partial. Use a BAA with the provider. |

## What Vela does not do

- It does not decide whether a use of AI is lawful, fair or proportionate.
- It does not detect every piece of personal data. Read the detection report and the threat model, and run your own labelled sample.
- It does not make the provider's processing compliant. Contracts, transfer assessments and provider due diligence remain yours.
- It has not yet had an independent security review (see `SECURITY.md`).
