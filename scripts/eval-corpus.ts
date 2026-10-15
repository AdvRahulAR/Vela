/**
 * Print detection precision/recall over tests/corpus. `--update` rewrites the
 * committed baseline (do this deliberately, when detection has improved).
 *   npm run eval            # report
 *   npm run eval -- --update
 */
import { writeFileSync } from 'node:fs';
import { evaluateCorpus, toBaseline, BASELINE_PATH } from '../tests/corpus/evaluate.js';

const r = evaluateCorpus();
const rows = Object.entries(r.byType).sort(([a], [b]) => a.localeCompare(b));
const pad = (s: string | number, n: number) => String(s).padEnd(n);

console.log(`Corpus: ${r.cases} cases\n`);
console.log(`${pad('type', 18)}${pad('expected', 10)}${pad('found', 8)}${pad('recall', 9)}false positives`);
for (const [t, s] of rows) {
  console.log(`${pad(t, 18)}${pad(s.expected, 10)}${pad(s.found, 8)}${pad(s.expected ? `${(s.recall * 100).toFixed(0)}%` : '-', 9)}${s.falsePositives}`);
}
console.log(`\nTotal false positives: ${r.falsePositives}`);
if (r.misses.length) {
  console.log('\nMissed:');
  for (const m of r.misses) console.log(`  ${m.type.padEnd(10)} ${JSON.stringify(m.value)}  in ${JSON.stringify(m.text)}`);
}
if (r.extras.length) {
  console.log('\nFalse positives:');
  for (const x of r.extras) console.log(`  ${x.type.padEnd(10)} ${JSON.stringify(x.value)}  in ${JSON.stringify(x.text)}`);
}

if (process.argv.includes('--update')) {
  writeFileSync(BASELINE_PATH, JSON.stringify(toBaseline(r), null, 2) + '\n');
  console.log(`\nBaseline written to ${BASELINE_PATH}`);
}
