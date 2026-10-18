/**
 * Detector packs (F10 in docs/COMPLIANCE_AUDIT.md): every labelled entity in
 * tests/corpus/packs/<pack>.jsonl is found, and negative lines find no pack type.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DETECTOR_PACKS, Vela, detectPii, resolvePacks } from '../src/index.js';

interface Case {
  text: string;
  entities: Array<{ type: string; value: string }>;
}

for (const pack of Object.keys(DETECTOR_PACKS)) {
  describe(`pack ${pack}`, () => {
    const cases = readFileSync(`tests/corpus/packs/${pack}.jsonl`, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as Case);
    const packTypes = new Set((DETECTOR_PACKS[pack] ?? []).map((p) => String(p.type)));
    const packs = resolvePacks([pack]);
    for (const c of cases) {
      it(c.entities.length ? `finds ${c.entities.map((e) => e.type).join(', ')}` : `no false positive: ${c.text}`, () => {
        const found = detectPii(c.text, { packs });
        for (const e of c.entities) {
          assert.ok(found.some((f) => f.type === e.type && f.value === e.value), `${e.type} "${e.value}" in ${JSON.stringify(found.map((f) => [f.type, f.value]))}`);
        }
        if (c.entities.length === 0) {
          assert.deepEqual(found.filter((f) => packTypes.has(String(f.type))).map((f) => [f.type, f.value]), []);
        }
      });
    }
  });
}

describe('packs through Vela', () => {
  it('pack entities are masked as placeholders and restored', () => {
    const vela = new Vela({ packs: ['pci'] });
    const s = vela.createSession();
    const masked = s.mask('CVV 123 and expiry 09/28');
    assert.equal(masked, 'CVV [CARD_CVV_1] and expiry [CARD_EXPIRY_1]');
    assert.equal(s.unmask(masked).text, 'CVV 123 and expiry 09/28');
  });
  it('unknown pack names are rejected', () => {
    assert.throws(() => new Vela({ packs: ['pcii'] }), /Unknown detector pack/);
  });
  it('pack regexes stay linear on adversarial input', () => {
    const inputs = ['9'.repeat(50_000), 'A1'.repeat(25_000), '1 '.repeat(25_000), '-1'.repeat(25_000), 'CVV '.repeat(12_000)];
    const packs = resolvePacks(Object.keys(DETECTOR_PACKS));
    for (const text of inputs) {
      const t = Date.now();
      detectPii(text, { packs, detectNames: false });
      assert.ok(Date.now() - t < 2000, `slow on ${text.slice(0, 10)}…`);
    }
  });
});
