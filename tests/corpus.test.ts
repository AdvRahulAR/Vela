/**
 * Detection-quality gate over tests/corpus. Structured identifiers must keep
 * 100% recall; heuristic types (PERSON, ADDRESS…) and the total false-positive
 * count must not get worse than tests/corpus/baseline.json.
 * Run `npm run eval` for the full report, `npm run eval -- --update` to accept
 * an improved baseline.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { evaluateCorpus, BASELINE_PATH, STRICT_TYPES } from './corpus/evaluate.js';

const report = evaluateCorpus();
const baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf8')) as { recall: Record<string, number>; falsePositives: number };

describe('Detection corpus', () => {
  it('structured identifiers keep 100% recall', () => {
    for (const t of STRICT_TYPES) {
      const s = report.byType[t];
      if (!s) continue;
      const missed = report.misses.filter((m) => m.type === t).map((m) => m.value);
      assert.equal(s.recall, 1, `${t} recall ${(s.recall * 100).toFixed(0)}%, missed: ${missed.join(', ')}`);
    }
  });

  it('recall does not regress below the baseline for any type', () => {
    for (const [t, base] of Object.entries(baseline.recall)) {
      const now = report.byType[t]?.recall ?? 0;
      assert.ok(Number(now.toFixed(4)) >= base, `${t} recall fell from ${base} to ${now.toFixed(4)} (run npm run eval)`);
    }
  });

  it('false positives do not exceed the baseline', () => {
    const extra = report.extras.map((x) => `${x.type}:${x.value}`).join(', ');
    assert.ok(report.falsePositives <= baseline.falsePositives, `false positives ${report.falsePositives} > ${baseline.falsePositives}: ${extra}`);
  });
});
