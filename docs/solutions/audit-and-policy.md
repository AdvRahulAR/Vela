# Audit evidence and policy (F3, F4)

**Symptom.** Nothing showed a regulator or auditor that Vela had worked on a given request. Every rule ("never send card numbers", "only to Azure India") had to be expressed in code.

**Root cause.** Vela was designed as a developer library. Its only output about its own behaviour was optional count logs, and its only action was to mask.

**Fix.**
- `src/core/audit.ts`:
  - value-free events, written before forwarding (fail closed with `VelaAuditError`) and after the response;
  - a hash-chained JSONL sink and `verifyAuditChain`.
- `src/core/policy.ts`:
  - a declarative policy with per-entity actions and request rules;
  - strict validation: unknown keys and actions are errors;
  - a canonical hash, recorded in every audit event.
- Request rules run in `enforceRequestPolicy` (gateway and wrappers) before any masking.

**Invariants.**
- Audit output follows CLAUDE.md invariant 4: no values, and no hashes of values.
- A policy typo must fail loudly. A silently ignored `entitys:` key would quietly weaken the control.

**Guarding tests.**
- `tests/audit.test.ts`: the leak oracle over the audit file, chain verification and tampering, sink failure returns 503 with nothing sent.
- `tests/policy.test.ts`: the YAML and JSON forms hash the same, typos are rejected, every action, the allowlists and non-text rules, and the schema stays in sync with the code.
