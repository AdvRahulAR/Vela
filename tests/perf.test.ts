/**
 * ReDoS and performance guard. The proxy runs every detector regex on
 * untrusted input, so catastrophic backtracking is a denial-of-service bug.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { detectPii, Vela } from '../src/index.js';
import { __detectorRegexesForTests as R } from '../src/core/detector.js';

const PER_REGEX_MS = Number(process.env.VELA_REDOS_MS ?? 250);
const REPEAT = 20_000;

/** Inputs designed to trigger backtracking in the patterns we use. */
const ADVERSARIAL: Record<string, string> = {
  words: 'a '.repeat(REPEAT),
  titleWords: 'Aa '.repeat(REPEAT),
  upperWords: 'AA '.repeat(REPEAT),
  digitsDots: '1.'.repeat(REPEAT),
  digitsSpaces: '1 '.repeat(REPEAT),
  digitsDashes: '1-'.repeat(REPEAT),
  atSigns: 'a@'.repeat(REPEAT),
  emailish: `${'a.'.repeat(REPEAT)}@`,
  hexColons: '0a:'.repeat(REPEAT),
  sectors: 'Sector 1, '.repeat(REPEAT / 5),
  addressTail: `12 MG Road${', Abc Def Ghi'.repeat(REPEAT / 10)}`,
  labelled: `Address: ${'x '.repeat(REPEAT)}`,
  versus: 'Ab v. Cd '.repeat(REPEAT / 5),
  partyChain: `${'Ab Of '.repeat(REPEAT / 5)}v. Cd (2019) 3`,
  ibanNearMiss: `GB82${' WEST'.repeat(REPEAT / 5)}`,
  keyValue: `password=${'a'.repeat(REPEAT)}`,
  base64: `aws secret ${'A/'.repeat(REPEAT)}`,
};

function timeRegex(re: RegExp, input: string): number {
  const r = new RegExp(re.source, re.flags);
  const t0 = performance.now();
  let n = 0;
  while (r.exec(input) !== null && n++ < 1e6) if (r.lastIndex === 0) break;
  return performance.now() - t0;
}

describe('ReDoS guard', () => {
  const all: Array<[string, RegExp]> = [
    ...R.builtin.map((p, i) => [`${String(p.type)}#${i}`, p.regex] as [string, RegExp]),
    ...Object.entries(R.names),
  ];
  for (const [name, re] of all) {
    it(`${name} stays linear on adversarial input`, () => {
      for (const [label, input] of Object.entries(ADVERSARIAL)) {
        const ms = timeRegex(re, input);
        assert.ok(ms < PER_REGEX_MS, `${name} took ${ms.toFixed(0)} ms on "${label}" (${input.length} chars)`);
      }
    });
  }
});

describe('Pipeline performance', () => {
  const unit =
    'Dear Mr. Rahul Sharma, your PAN ABCDE1234F and card 4111 1111 1111 1111 are on file. ' +
    'Email test@domain.com, call +91 98765 43210. Office: 12 MG Road, Bengaluru 560001. ' +
    'See State of Kerala v. Rahul Sharma (2019) 3 SCC 123. नमस्ते 🙂\n';

  it('detects across a large document within a bounded time', () => {
    const doc = unit.repeat(Math.ceil(250_000 / unit.length));
    const t0 = performance.now();
    detectPii(doc);
    const ms = performance.now() - t0;
    assert.ok(ms < Number(process.env.VELA_DOC_MS ?? 5000), `250 KB document took ${ms.toFixed(0)} ms`);
  });

  it('mask time grows roughly linearly with input size', () => {
    const vela = new Vela({ fpeKey: new Uint8Array(32).fill(7) });
    // Best of 3 runs per size: other test files run in parallel, so single timings are noisy.
    const time = (n: number) => {
      const text = unit.repeat(n);
      vela.mask(text); // warm-up
      let best = Infinity;
      for (let i = 0; i < 3; i++) {
        const t0 = performance.now();
        vela.mask(text);
        best = Math.min(best, performance.now() - t0);
      }
      return best;
    };
    const small = time(200);
    const large = time(800);
    // 4x input: allow up to 10x time for CI noise; a quadratic blow-up would be ~16x.
    assert.ok(large < Math.max(small * 10, 100), `200 units: ${small.toFixed(0)} ms, 800 units: ${large.toFixed(0)} ms`);
  });
});
