/**
 * Property-based tests: random prose interleaved with generated, valid PII.
 * Run count: VELA_PBT_RUNS (default 200). On failure fast-check prints the seed
 * and a shrunk counterexample; re-run with VELA_PBT_SEED=<seed> to reproduce.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import {
  Vela,
  generateVerhoeffChecksum,
  validateVerhoeff,
  luhnCheckDigit,
  validateLuhn,
  validateIban,
  validateGstin,
  gstinCheckChar,
} from '../src/index.js';

const RUNS = Number(process.env.VELA_PBT_RUNS ?? 200);
const SEED = process.env.VELA_PBT_SEED !== undefined ? Number(process.env.VELA_PBT_SEED) : undefined;
const params = { numRuns: RUNS, ...(SEED !== undefined ? { seed: SEED } : {}) };

const KEY = new Uint8Array(32).fill(7);
const vela = new Vela({ fpeKey: KEY, customDetectors: [{ name: 'emp', type: 'EMP_ID', regex: /\bEMP-\d{5}\b/g }] });

// ── Generators ─────────────────────────────────────────────────────────────
const digits = (n: number) => fc.array(fc.integer({ min: 0, max: 9 }), { minLength: n, maxLength: n }).map((a) => a.join(''));
const upper = (n: number) =>
  fc.array(fc.integer({ min: 65, max: 90 }), { minLength: n, maxLength: n }).map((a) => String.fromCharCode(...a));
const lower = (min: number, max: number) =>
  fc.array(fc.integer({ min: 97, max: 122 }), { minLength: min, maxLength: max }).map((a) => String.fromCharCode(...a));

const aadhaar = fc.tuple(fc.integer({ min: 2, max: 9 }), digits(10)).map(([d, rest]) => {
  const body = `${d}${rest}`;
  const n = `${body}${generateVerhoeffChecksum(body)}`;
  return `${n.slice(0, 4)} ${n.slice(4, 8)} ${n.slice(8)}`;
});
const card = digits(14).map((d) => {
  const body = `4${d}`;
  return `${body}${luhnCheckDigit(body)}`;
});
const pan = fc.tuple(upper(3), upper(1), digits(4), upper(1)).map(([a, b, n, c]) => `${a}P${b}${n}${c}`);
const gstinFor = (p: string) =>
  fc.tuple(fc.integer({ min: 1, max: 37 }), fc.integer({ min: 1, max: 9 })).map(([st, ent]) => {
    const first14 = `${String(st).padStart(2, '0')}${p}${ent}Z`;
    return `${first14}${gstinCheckChar(first14)}`;
  });
const iban = digits(14).map((d) => {
  const bban = `WEST${d}`;
  const rearranged = `${bban}GB00`.replace(/[A-Z]/g, (ch) => String(ch.charCodeAt(0) - 55));
  let rem = 0;
  for (const ch of rearranged) rem = (rem * 10 + Number(ch)) % 97;
  return `GB${String(98 - rem).padStart(2, '0')}${bban}`;
});
const email = fc.tuple(lower(3, 8), lower(3, 8)).map(([u, d]) => `${u}@${d}.com`);
const phone = digits(9).map((d) => `+91 9${d}`);
const empId = digits(5).map((d) => `EMP-${d}`);
const FIRST = ['Rahul', 'Priya', 'Arjun', 'Deepa', 'Joseph', 'Anita', 'Vikram', 'Meera'];
const LAST = ['Sharma', 'Menon', 'Nair', 'Iyer', 'Mathew', 'Desai', 'Reddy', 'Kapoor'];
const person = fc.tuple(fc.constantFrom(...FIRST), fc.constantFrom(...LAST)).map(([f, l]) => `${f} ${l}`);

interface Pii {
  type: string;
  value: string;
}
const pii: fc.Arbitrary<Pii> = fc.oneof(
  aadhaar.map((value) => ({ type: 'AADHAAR', value })),
  card.map((value) => ({ type: 'CREDIT_CARD', value })),
  pan.map((value) => ({ type: 'PAN', value })),
  iban.map((value) => ({ type: 'IBAN', value })),
  email.map((value) => ({ type: 'EMAIL', value })),
  phone.map((value) => ({ type: 'PHONE', value })),
  empId.map((value) => ({ type: 'EMP_ID', value })),
  person.map((value) => ({ type: 'PERSON', value })),
);

// Filler: plain words, Indian and CJK scripts, emoji, and literal placeholder-shaped text.
const WORDS = ['the', 'invoice', 'was', 'sent', 'to', 'please', 'call', 'about', 'case', 'and', 'नमस्ते', 'धन्यवाद', '你好', '谢谢', '🙂', '📎', '[EMAIL_3]', '[PERSON_9]'];
const filler = fc.array(fc.constantFrom(...WORDS), { minLength: 1, maxLength: 6 }).map((w) => w.join(' '));

/** A document: filler / PII / filler / PII …, separated so entities never touch. */
const doc = fc.array(fc.tuple(filler, pii), { minLength: 1, maxLength: 6 }).chain((parts) =>
  filler.map((tail) => ({
    text: parts.map(([f, p]) => `${f}, ${p.value}, `).join('') + tail,
    pii: parts.map(([, p]) => p),
  })),
);

// ── Properties ─────────────────────────────────────────────────────────────
describe('Properties', () => {
  it('mask → unmask is the identity (fresh session and shared sessionId)', () => {
    fc.assert(
      fc.property(doc, fc.boolean(), ({ text }, shared) => {
        const s = vela.createSession(shared ? { sessionId: 'conv-1' } : {});
        const masked = s.mask(text);
        assert.equal(s.unmask(masked).text, text);
      }),
      params,
    );
  });

  it('no inserted PII value appears in the masked text', () => {
    fc.assert(
      fc.property(doc, ({ text, pii: items }) => {
        const masked = vela.mask(text).text;
        for (const p of items) assert.ok(!masked.includes(p.value), `${p.type} ${p.value} leaked: ${masked}`);
      }),
      params,
    );
  });

  it('FPE output is structurally valid and never equals the input', () => {
    const validators: Record<string, (v: string) => boolean> = {
      AADHAAR: (v) => validateVerhoeff(v.replace(/\D/g, '')),
      CREDIT_CARD: (v) => validateLuhn(v),
      IBAN: (v) => validateIban(v),
      PAN: (v) => /^[A-Z]{3}P[A-Z]\d{4}[A-Z]$/.test(v),
      PHONE: (v) => /^\+91 [6-9]\d{9}$/.test(v),
    };
    fc.assert(
      fc.property(doc, ({ text }) => {
        const r = vela.mask(text);
        for (const rep of r.replacements ?? []) {
          if (rep.method !== 'fpe') continue;
          assert.notEqual(rep.masked, rep.original);
          const ok = validators[rep.type];
          if (ok) assert.ok(ok(rep.masked), `${rep.type} ${rep.original} -> ${rep.masked} is not valid`);
        }
      }),
      params,
    );
  });

  it('a GSTIN embedding a PAN stays valid and matches the masked PAN', () => {
    fc.assert(
      fc.property(
        pan.chain((p) => gstinFor(p).map((g) => ({ p, g }))),
        ({ p, g }) => {
          const r = vela.mask(`PAN ${p} and GSTIN ${g}`);
          const reps = r.replacements ?? [];
          const mp = reps.find((x) => x.type === 'PAN')?.masked;
          const mg = reps.find((x) => x.type === 'GSTIN')?.masked;
          assert.ok(mp && mg, r.text);
          assert.ok(validateGstin(mg), `invalid masked GSTIN ${mg}`);
          assert.equal(mg.slice(2, 12), mp);
        },
      ),
      params,
    );
  });

  it('streaming restore equals one-shot restore for any chunking', () => {
    fc.assert(
      fc.property(doc, fc.array(fc.integer({ min: 1, max: 12 }), { minLength: 1, maxLength: 40 }), ({ text }, cuts) => {
        const s = vela.createSession();
        const masked = s.mask(text);
        const stream = s.createStreamDeMasker();
        let out = '';
        let pos = 0;
        let i = 0;
        while (pos < masked.length) {
          const n = cuts[i++ % cuts.length] as number;
          out += stream.feed(masked.slice(pos, pos + n));
          pos += n;
        }
        out += stream.flush();
        assert.equal(out, s.unmask(masked).text);
      }),
      params,
    );
  });

  it('JSON values stay serialisable and round-trip', () => {
    const key = fc.constantFrom('name', 'note', 'contact', 'customer_name', 'body');
    const obj = fc.dictionary(key, doc.map((d) => d.text), { minKeys: 1, maxKeys: 4, noNullPrototype: true });
    fc.assert(
      fc.property(fc.array(obj, { minLength: 1, maxLength: 3 }), (value) => {
        const s = vela.createSession();
        const masked = s.maskValue(value);
        const reparsed = JSON.parse(JSON.stringify(masked)) as unknown;
        assert.deepEqual(s.unmaskValue(reparsed), value);
      }),
      params,
    );
  });

  it('same key + sessionId is deterministic; without sessionId FPE values differ', () => {
    fc.assert(
      fc.property(doc, ({ text }) => {
        const a = vela.createSession({ sessionId: 'stable' }).mask(text);
        const b = vela.createSession({ sessionId: 'stable' }).mask(text);
        assert.equal(a, b);
        const r1 = vela.mask(text);
        const r2 = vela.mask(text);
        if ((r1.replacements ?? []).some((x) => x.method === 'fpe')) assert.notEqual(r1.text, r2.text);
      }),
      params,
    );
  });
});
