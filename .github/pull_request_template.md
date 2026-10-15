## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `npm run typecheck`, `npm run lint` and `npm test` pass locally
- [ ] Detection change? Added positive **and** negative cases to `tests/corpus/*.jsonl`; updated the baseline only if numbers improved (`npm run eval -- --update`)
- [ ] Changes masked or restored output for already-detected input? Marked as a **minor** version bump (see CONTRIBUTING.md)
- [ ] `CHANGELOG.md` entry under the next version
- [ ] README / docs updated if behaviour or options changed
- [ ] Tests use synthetic data only, no real personal data
