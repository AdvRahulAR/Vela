/**
 * Gate over the synthetic corpus (npm run gen-corpus): structured identifiers
 * keep 100% recall, other types and the false-positive count don't regress
 * below tests/corpus/generated/baseline.json. Regenerate the report with
 * `npm run eval -- --generated --report`.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { evaluateCorpus, loadCorpus, GENERATED_DIR, GENERATED_BASELINE_PATH, STRICT_TYPES } from './corpus/evaluate.js';

const report = evaluateCorpus(loadCorpus(GENERATED_DIR));
const baseline = JSON.parse(readFileSync(GENERATED_BASELINE_PATH, 'utf8')) as { recall: Record<string, number>; falsePositives: number };

describe('Synthetic detection corpus', () => {
  it('has a meaningful size', () => {
    assert.ok(Object.values(report.byType).reduce((a, s) => a + s.expected, 0) >= 2000);
  });
  it('structured identifiers keep 100% recall', () => {
    for (const t of STRICT_TYPES) {
      const s = report.byType[t];
      if (s) assert.equal(s.recall, 1, `${t}: ${report.misses.filter((m) => m.type === t).slice(0, 3).map((m) => m.value).join(', ')}`);
    }
  });
  it('no type regresses below the baseline', () => {
    for (const [t, base] of Object.entries(baseline.recall)) {
      assert.ok((report.byType[t]?.recall ?? 0) >= base - 1e-9, `${t} recall ${report.byType[t]?.recall} < baseline ${base}`);
    }
    assert.ok(report.falsePositives <= baseline.falsePositives, `false positives ${report.falsePositives} > baseline ${baseline.falsePositives}`);
  });
});
