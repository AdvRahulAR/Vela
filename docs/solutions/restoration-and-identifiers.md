# Tool-call restoration and real-looking identifiers (F5, F7)

**Symptom.**
- A prompt-injected model could put `[EMAIL_1]` into a tool URL, and Vela restored the real address there.
- FPE output for Aadhaar, cards, GSTIN and IBAN passed its checksum, so it could equal a real third party's identifier.

**Root cause.** Both were deliberate design choices (restore everywhere, keep structure valid) with no way to opt out per field or per type.

**Fix.**
- Restore policy:
  - each restored string is attributed to a field (`content`, `tool_args`, `thinking`), via `fieldForKey` in `src/core/streaming.ts` and lane kinds in the stream unmaskers;
  - `MaskSession.restoreOptions` applies `keep` per the policy and counts what it did.
- `fpe-synthetic` action: `invalidateCheck` in `src/core/fpe.ts` changes the check character after encryption. Types without one fall back to a placeholder.

**Invariant.** Any restoration into a new response field must go through `restoreOptions` with the right field. Otherwise the policy can't see it.

**Guarding tests.**
- `tests/restore-policy.test.ts`: OpenAI non-streamed and Anthropic streamed tool arguments, plus the report counts.
- `tests/policy.test.ts`: "fpe-synthetic output fails its checksum and still restores".
