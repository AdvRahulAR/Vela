/**
 * Detection-quality evaluation over the labelled corpus in tests/corpus/*.jsonl.
 * An expected entity counts as found only if an entity of the same type and the
 * exact same value is detected; anything else detected is a false positive.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { detectPii } from '../../src/index.js';

export const CORPUS_DIR = __dirname;
export const BASELINE_PATH = join(CORPUS_DIR, 'baseline.json');
/** Synthetic corpus written by `npm run gen-corpus`. */
export const GENERATED_DIR = join(CORPUS_DIR, 'generated');
export const GENERATED_BASELINE_PATH = join(GENERATED_DIR, 'baseline.json');

/** Wilson score interval (95% by default) for k successes out of n. */
export function wilson(k: number, n: number, z = 1.96): [number, number] {
  if (n === 0) return [0, 1];
  const p = k / n;
  const d = 1 + (z * z) / n;
  const centre = p + (z * z) / (2 * n);
  const margin = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [Math.max(0, (centre - margin) / d), Math.min(1, (centre + margin) / d)];
}

/** Types whose recall must stay at 100%: deterministic formats with no excuse to miss. */
export const STRICT_TYPES = [
  'AADHAAR', 'PAN', 'GSTIN', 'CREDIT_CARD', 'IBAN', 'IFSC', 'EMAIL', 'SECRET_KEY', 'JWT', 'MAC_ADDRESS',
  'PHONE', 'SSN', 'UPI_ID', 'PASSPORT', 'VOTER_ID', 'DRIVING_LICENCE', 'BANK_ACCOUNT', 'IP_ADDRESS',
];

interface Case {
  file: string;
  text: string;
  entities: Array<{ type: string; value: string }>;
  tags?: string[];
}

export interface TypeStats {
  expected: number;
  found: number;
  falsePositives: number;
  recall: number;
}

export interface CorpusReport {
  cases: number;
  byType: Record<string, TypeStats>;
  falsePositives: number;
  misses: Array<{ file: string; text: string; type: string; value: string }>;
  extras: Array<{ file: string; text: string; type: string; value: string }>;
}

export function loadCorpus(dir = CORPUS_DIR): Case[] {
  const out: Case[] = [];
  for (const f of readdirSync(dir).filter((n) => n.endsWith('.jsonl')).sort()) {
    const lines = readFileSync(join(dir, f), 'utf8').split(/\r?\n/);
    lines.forEach((line, i) => {
      if (!line.trim()) return;
      try {
        out.push({ file: f, ...(JSON.parse(line) as Omit<Case, 'file'>) });
      } catch (e) {
        throw new Error(`${f}:${i + 1}: invalid JSON (${(e as Error).message})`);
      }
    });
  }
  return out;
}

export function evaluateCorpus(cases = loadCorpus()): CorpusReport {
  const byType: Record<string, TypeStats> = {};
  const stat = (t: string) => (byType[t] ??= { expected: 0, found: 0, falsePositives: 0, recall: 1 });
  const misses: CorpusReport['misses'] = [];
  const extras: CorpusReport['extras'] = [];

  for (const c of cases) {
    const detected = detectPii(c.text).map((e) => ({ type: String(e.type), value: e.value }));
    const unmatched = [...detected];
    for (const exp of c.entities) {
      const s = stat(exp.type);
      s.expected++;
      const i = unmatched.findIndex((d) => d.type === exp.type && d.value === exp.value);
      if (i >= 0) {
        s.found++;
        unmatched.splice(i, 1);
      } else {
        misses.push({ file: c.file, text: c.text, ...exp });
      }
    }
    for (const d of unmatched) {
      stat(d.type).falsePositives++;
      extras.push({ file: c.file, text: c.text, ...d });
    }
  }
  for (const s of Object.values(byType)) s.recall = s.expected ? s.found / s.expected : 1;
  return { cases: cases.length, byType, falsePositives: extras.length, misses, extras };
}

/** Baseline: per-type recall and total false positives, committed to the repo. */
export function toBaseline(r: CorpusReport): { recall: Record<string, number>; falsePositives: number } {
  const recall: Record<string, number> = {};
  for (const [t, s] of Object.entries(r.byType).sort()) if (s.expected) recall[t] = Number(s.recall.toFixed(4));
  return { recall, falsePositives: r.falsePositives };
}
