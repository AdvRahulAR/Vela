# Contributing to vela-privacy

## Setup

```bash
npm ci
npm run build
```

Node 18.19 or newer is needed to run the tests. Use Node 22 for coverage.

## Checks

Run all of these before opening a pull request. CI runs the same steps on Node 18, 20, 22 and 24 (Linux) and Node 22 (Windows).

| Command | What it does |
|---|---|
| `npm run typecheck` | TypeScript, strict mode |
| `npm run lint` | ESLint, including unhandled-promise checks |
| `npm test` | All suites: unit, regressions, property-based, detection corpus, ReDoS/performance |
| `npm run coverage` | Tests with coverage; fails below the thresholds in `package.json` |
| `npm run smoke` | Builds, packs and installs the package in a clean folder, then checks `require`, `import` and the CLI |
| `npm run eval` | Prints detection precision and recall per entity type over `tests/corpus` |

Property tests run 200 cases each by default. For a deeper run:

```bash
VELA_PBT_RUNS=5000 npm test
```

A failing property test prints a seed. Reproduce it with `VELA_PBT_SEED=<seed> npm test`.

## Changing detection

Every change to a detector, the name heuristics or the citation rules must add cases to `tests/corpus/*.jsonl`:

- one line per case: `{"text": "...", "entities": [{"type": "PERSON", "value": "..."}], "tags": ["..."]}`
- label **every** entity in the text, so anything extra counts as a false positive
- add negative cases (text that must not be detected) as well as positive ones

The corpus test fails if any structured identifier type drops below 100% recall, or if recall for any type or the total false-positive count gets worse than `tests/corpus/baseline.json`. When your change improves the numbers, accept them deliberately:

```bash
npm run eval -- --update
```

Commit the new baseline with the change that earned it.

## Versioning

While the package is 0.x:

- **minor** (0.x.0): any change to the masked or restored output for input that was already detected, any new required option, or any removed export
- **patch** (0.x.y): fixes that only add detections, remove false positives, or fix crashes, and new optional settings

## Releasing

Releases are published by `.github/workflows/release.yml`, never from a laptop (`npm publish` refuses outside GitHub Actions).

1. Bump `version` in `package.json`, `package-lock.json` and `PACKAGE_VERSION` in `src/config/constants.ts`.
2. Add a `## <version>` section at the top of `CHANGELOG.md`.
3. Merge to `main`.
4. Tag and push:

   ```bash
   git tag v0.3.3
   git push origin v0.3.3
   ```

The workflow runs the full test matrix, checks that the tag, version and changelog agree, publishes to npm with provenance and creates the GitHub release.
