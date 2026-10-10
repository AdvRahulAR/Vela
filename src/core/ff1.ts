import { createCipheriv, type Cipher } from 'node:crypto';

/**
 * NIST SP 800-38G (Rev. 1) FF1 format-preserving encryption.
 *
 * Implemented directly against the specification (AES CBC-MAC PRF, 10-round
 * Feistel) and verified against the official NIST FF1 sample vectors in
 * tests/ff1.test.ts. Supports radix 2..65536 over an arbitrary alphabet.
 */
export class FF1 {
  private readonly radix: number;
  private readonly bigRadix: bigint;
  private readonly alphabet: string;
  private readonly ecb: Cipher;
  private readonly tweak: Uint8Array;

  constructor(key: Uint8Array, tweak: Uint8Array = new Uint8Array(0), alphabet = '0123456789') {
    if (![16, 24, 32].includes(key.length)) {
      throw new Error('FF1 key must be 16, 24 or 32 bytes');
    }
    const chars = Array.from(alphabet);
    if (chars.length < 2 || new Set(chars).size !== chars.length) {
      throw new Error('FF1 alphabet must contain at least 2 unique characters');
    }
    this.alphabet = alphabet;
    this.radix = chars.length;
    this.bigRadix = BigInt(this.radix);
    this.tweak = tweak;
    const algo = key.length === 16 ? 'aes-128-ecb' : key.length === 24 ? 'aes-192-ecb' : 'aes-256-ecb';
    // A single ECB instance is reused as the raw block cipher (never finalised).
    this.ecb = createCipheriv(algo, key, null);
    this.ecb.setAutoPadding(false);
  }

  encrypt(input: string, tweak: Uint8Array = this.tweak): string {
    return this.cipher(input, tweak, true);
  }

  decrypt(input: string, tweak: Uint8Array = this.tweak): string {
    return this.cipher(input, tweak, false);
  }

  /** Minimum length so that radix^len >= 1,000,000 (NIST SP 800-38G Rev.1 domain requirement). */
  minLength(): number {
    return Math.max(2, Math.ceil(6 / Math.log10(this.radix)));
  }

  private block(input: Buffer): Buffer {
    return this.ecb.update(input);
  }

  private prf(data: Buffer): Buffer {
    let y: Buffer = Buffer.alloc(16);
    for (let off = 0; off < data.length; off += 16) {
      const x = Buffer.alloc(16);
      for (let j = 0; j < 16; j++) x[j] = (y[j] ?? 0) ^ (data[off + j] ?? 0);
      y = this.block(x);
    }
    return y;
  }

  private num(s: string): bigint {
    let r = 0n;
    for (const ch of s) {
      const idx = this.alphabet.indexOf(ch);
      if (idx < 0) throw new Error('FF1: character outside alphabet');
      r = r * this.bigRadix + BigInt(idx);
    }
    return r;
  }

  private str(x: bigint, m: number): string {
    const out: string[] = new Array(m);
    for (let i = m - 1; i >= 0; i--) {
      out[i] = this.alphabet[Number(x % this.bigRadix)] as string;
      x /= this.bigRadix;
    }
    return out.join('');
  }

  private cipher(X: string, T: Uint8Array, encrypt: boolean): string {
    const n = X.length;
    if (n < 2) throw new Error('FF1: input too short');
    if (this.bigRadix ** BigInt(n) < 1_000_000n) {
      throw new Error('FF1: domain smaller than NIST minimum (radix^n >= 10^6)');
    }
    const t = T.length;
    const u = Math.floor(n / 2);
    const v = n - u;
    const bits = (this.bigRadix ** BigInt(v) - 1n).toString(2).length;
    const b = Math.ceil(bits / 8);
    const d = 4 * Math.ceil(b / 4) + 4;

    const P = Buffer.from([
      1, 2, 1,
      (this.radix >> 16) & 0xff, (this.radix >> 8) & 0xff, this.radix & 0xff,
      10, u & 0xff,
      (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff,
      (t >>> 24) & 0xff, (t >>> 16) & 0xff, (t >>> 8) & 0xff, t & 0xff,
    ]);
    const pad = (((-t - b - 1) % 16) + 16) % 16;
    const qLen = t + pad + 1 + b;
    const modU = this.bigRadix ** BigInt(u);
    const modV = this.bigRadix ** BigInt(v);

    let A = X.slice(0, u);
    let B = X.slice(u);

    const roundY = (i: number, half: string): bigint => {
      const Q = Buffer.alloc(qLen);
      Buffer.from(T).copy(Q, 0);
      Q[t + pad] = i;
      let nb = this.num(half);
      for (let j = qLen - 1; j >= qLen - b; j--) {
        Q[j] = Number(nb & 0xffn);
        nb >>= 8n;
      }
      const R = this.prf(Buffer.concat([P, Q]));
      const blocks: Buffer[] = [R];
      for (let j = 1; j < Math.ceil(d / 16); j++) {
        const x = Buffer.alloc(16);
        for (let k = 0; k < 16; k++) x[k] = R[k] ?? 0;
        const jb = Buffer.alloc(16);
        jb.writeUInt32BE(j, 12);
        for (let k = 0; k < 16; k++) x[k] = (x[k] ?? 0) ^ (jb[k] ?? 0);
        blocks.push(this.block(x));
      }
      const S = Buffer.concat(blocks).subarray(0, d);
      return BigInt('0x' + S.toString('hex'));
    };

    if (encrypt) {
      for (let i = 0; i < 10; i++) {
        const m = i % 2 === 0 ? u : v;
        const mod = m === u ? modU : modV;
        const y = roundY(i, B);
        const c = (this.num(A) + y) % mod;
        A = B;
        B = this.str(c, m);
      }
    } else {
      for (let i = 9; i >= 0; i--) {
        const m = i % 2 === 0 ? u : v;
        const mod = m === u ? modU : modV;
        const y = roundY(i, A);
        let c = (this.num(B) - y) % mod;
        if (c < 0n) c += mod;
        B = A;
        A = this.str(c, m);
      }
    }
    return A + B;
  }
}
