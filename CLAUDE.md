# Vela: notes for agents and contributors

Vela masks personal data in LLM requests and restores it in responses. It is sold as a compliance control, so **a value reaching the provider unmasked is the worst bug this codebase can have**. Read `docs/THREAT_MODEL.md` before changing behaviour.

## Invariants (each one was learned from a real leak; see `docs/solutions/`)

1. **Fail closed.** If Vela can't mask a request (unknown route, unreadable body, invalid JSON, NER down, policy says block), it throws a `VelaError` and sends nothing. Never fall back to forwarding the original. Opening up is always an explicit, documented opt-in (`passthrough: 'all'`, `recognizerFailure: 'continue'`).
2. **Every provider route and SDK method is in the route matrix.** Adding or changing a route, format or wrapped method means adding a row to `tests/route-matrix.test.ts` as masked or blocked. `classifyRoute()` in `src/integrations/formats.ts` is the single source of truth for routes.
3. **Allowlist, never blocklist.** Enumerate what is safe to skip (read-only SDK methods, structural JSON keys), not what to block or mask. Anything unknown is masked (`maskResidual`) or rejected (`guardClient`, `classifyRoute`).
4. **No values in logs, errors or audit output.** Only counts, types, routes, timings and IDs. Not hashes of values either: short identifiers can be brute-forced.
5. **Detection changes come with corpus cases.** Positive and negative lines in `tests/corpus/*.jsonl`, every entity labelled, then `npm run eval -- --update` (see `CONTRIBUTING.md`).
6. **Leak tests use the oracle.** New fail-open tests send `SENTINEL_TEXT` from `tests/helpers/leak-oracle.ts` through the surface and call `assertNoSentinel` on what the mock upstream (or log, or audit sink) received.
7. **Synthetic data only**, in tests, docs and issues.

## Commands

```bash
npm run typecheck && npm run lint && npm test   # every change
npm run coverage                                # 95% lines / 81% branches / 86% functions
npm run smoke                                   # packed install, CJS + ESM + CLI
npm run eval                                    # detection corpus gate
```

Versioning on 0.x: a change to masked/restored output for already-detected input, or a new default that rejects requests, is a minor bump; added detections and new optional settings are a patch (security fixes may ship as a patch with a CHANGELOG note).

## Compound step

After fixing a gap: add a note to `docs/solutions/` (symptom, root cause, invariant, guarding test), add any new invariant here, and add a line to the fail-open checklist in `docs/REVIEW_GUIDE.md` if a reviewer could have caught it.
