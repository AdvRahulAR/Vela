import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FF1 } from '../src/core/ff1.js';

const K128 = '2B7E151628AED2A6ABF7158809CF4F3C';
const K192 = K128 + 'EF4359D8D580AA4F';
const K256 = K192 + '7F036D6F04FC6A94';
const R36 = '0123456789abcdefghijklmnopqrstuvwxyz';
const T1 = '39383736353433323130';
const T3 = '3737373770717273373737';

// Official NIST FF1 sample vectors (FF1samples.pdf, Samples 1-9)
const VECTORS: Array<[string, string, string, string, string]> = [
  [K128, '', '0123456789', '0123456789', '2433477484'],
  [K128, T1, '0123456789', '0123456789', '6124200773'],
  [K128, T3, R36, '0123456789abcdefghi', 'a9tv40mll9kdu509eum'],
  [K192, '', '0123456789', '0123456789', '2830668132'],
  [K192, T1, '0123456789', '0123456789', '2496655549'],
  [K192, T3, R36, '0123456789abcdefghi', 'xbj3kv35jrawxv32ysr'],
  [K256, '', '0123456789', '0123456789', '6657667009'],
  [K256, T1, '0123456789', '0123456789', '1001623463'],
  [K256, T3, R36, '0123456789abcdefghi', 'xs8a0azh2avyalyzuwd'],
];

describe('FF1 (NIST SP 800-38G)', () => {
  VECTORS.forEach(([k, t, alphabet, pt, ct], i) => {
    it(`matches NIST sample ${i + 1}`, () => {
      const f = new FF1(Buffer.from(k, 'hex'), Buffer.from(t, 'hex'), alphabet);
      assert.equal(f.encrypt(pt), ct);
      assert.equal(f.decrypt(ct), pt);
    });
  });

  it('rejects domains below 10^6', () => {
    const f = new FF1(Buffer.alloc(32, 1));
    assert.throws(() => f.encrypt('12345'));
    assert.equal(f.encrypt('123456').length, 6);
  });
});
