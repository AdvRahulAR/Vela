import { createHash } from 'node:crypto';
import { FF1 } from './ff1.js';
import { generateVerhoeffChecksum } from './algorithms/verhoeff.js';
import { luhnCheckDigit } from './algorithms/luhn.js';
import { gstinCheckChar } from './algorithms/gstin.js';
import { DIGITS } from '../config/constants.js';
import type { EntityType } from '../types.js';

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const MIN_DOMAIN = 1_000_000n;
const MAX_WALK = 10_000;

/** Entity types that have a format-preserving handler. Others fall back to tokens. */
export const STRUCTURED_TYPES: readonly EntityType[] = [
  'AADHAAR',
  'PAN',
  'GSTIN',
  'CREDIT_CARD',
  'PHONE',
  'SSN',
  'IBAN',
  'IP_ADDRESS',
  'BANK_ACCOUNT',
  'PASSPORT',
  'IFSC',
];

type Slot = { kind: 'fixed' } | { kind: 'var'; alphabet: string } | { kind: 'derived' };

interface Template {
  chars: string[];
  slots: Slot[];
  /** Fill derived slots (check digits) from the variable ones. */
  finalize?: (chars: string[]) => void;
  /** Extra validity constraint enforced by cycle-walking. */
  accept?: (chars: string[]) => boolean;
}

function classAlphabet(ch: string): string | null {
  if (ch >= '0' && ch <= '9') return DIGITS;
  if (ch >= 'A' && ch <= 'Z') return UPPER;
  if (ch >= 'a' && ch <= 'z') return LOWER;
  return null;
}

/** Character-class preserving template: digits stay digits, letters keep case, punctuation is fixed. */
function genericTemplate(value: string): Template {
  const chars = Array.from(value);
  const slots: Slot[] = chars.map((c) => {
    const a = classAlphabet(c);
    return a ? { kind: 'var', alphabet: a } : { kind: 'fixed' };
  });
  return { chars, slots };
}

/** Positions of characters matching `re` within the value. */
function positions(chars: string[], re: RegExp): number[] {
  const out: number[] = [];
  chars.forEach((c, i) => {
    if (re.test(c)) out.push(i);
  });
  return out;
}

function fixedSlots(n: number): Slot[] {
  return Array.from({ length: n }, () => ({ kind: 'fixed' }) as Slot);
}

function aadhaarTemplate(value: string): Template | null {
  const chars = Array.from(value);
  const d = positions(chars, /\d/);
  if (d.length !== 12) return null;
  const slots = fixedSlots(chars.length);
  d.forEach((p, i) => {
    if (i === 0) slots[p] = { kind: 'var', alphabet: '23456789' };
    else if (i === 11) slots[p] = { kind: 'derived' };
    else slots[p] = { kind: 'var', alphabet: DIGITS };
  });
  const last = d[11] as number;
  return {
    chars,
    slots,
    finalize: (c) => {
      const payload = d.slice(0, 11).map((p) => c[p]).join('');
      c[last] = String(generateVerhoeffChecksum(payload));
    },
  };
}

function cardTemplate(value: string): Template | null {
  const chars = Array.from(value);
  const d = positions(chars, /\d/);
  if (d.length < 13 || d.length > 19) return null;
  const slots = fixedSlots(chars.length);
  const keep = chars[d[0] as number] === '3' && /[47]/.test(chars[d[1] as number] ?? '') ? 2 : 1;
  d.forEach((p, i) => {
    if (i < keep) slots[p] = { kind: 'fixed' };
    else if (i === d.length - 1) slots[p] = { kind: 'derived' };
    else slots[p] = { kind: 'var', alphabet: DIGITS };
  });
  const last = d[d.length - 1] as number;
  return {
    chars,
    slots,
    finalize: (c) => {
      const payload = d.slice(0, -1).map((p) => c[p]).join('');
      c[last] = String(luhnCheckDigit(payload));
    },
  };
}

function panTemplate(value: string): Template | null {
  const chars = Array.from(value);
  if (chars.length !== 10) return null;
  const t = genericTemplate(value);
  // 4th character encodes the holder type (P = person, C = company, ...) — keep it.
  t.slots[3] = { kind: 'fixed' };
  return t;
}

function ssnTemplate(value: string): Template | null {
  const chars = Array.from(value);
  const d = positions(chars, /\d/);
  if (d.length !== 9) return null;
  const slots = fixedSlots(chars.length);
  for (const p of d) slots[p] = { kind: 'var', alphabet: DIGITS };
  return {
    chars,
    slots,
    accept: (c) => {
      const s = d.map((p) => c[p]).join('');
      const area = s.slice(0, 3);
      return area !== '000' && area !== '666' && area[0] !== '9' && s.slice(3, 5) !== '00' && s.slice(5) !== '0000';
    },
  };
}

function ibanTemplate(value: string): Template | null {
  const chars = Array.from(value);
  const a = positions(chars, /[A-Za-z0-9]/);
  if (a.length < 15) return null;
  const slots = fixedSlots(chars.length);
  a.forEach((p, i) => {
    if (i < 2) slots[p] = { kind: 'fixed' };
    else if (i < 4) slots[p] = { kind: 'derived' };
    else slots[p] = { kind: 'var', alphabet: classAlphabet(chars[p] as string) ?? DIGITS };
  });
  return {
    chars,
    slots,
    finalize: (c) => {
      const core = a.map((p) => (c[p] as string).toUpperCase());
      const rearranged = core.slice(4).join('') + core[0] + core[1] + '00';
      let rem = 0;
      for (const ch of rearranged) {
        const v = ch >= 'A' && ch <= 'Z' ? String(ch.charCodeAt(0) - 55) : ch;
        for (const digit of v) rem = (rem * 10 + Number(digit)) % 97;
      }
      const check = String(98 - rem).padStart(2, '0');
      c[a[2] as number] = check[0] as string;
      c[a[3] as number] = check[1] as string;
    },
  };
}

function ifscTemplate(value: string): Template | null {
  const chars = Array.from(value);
  if (chars.length !== 11) return null;
  const t = genericTemplate(value);
  for (let i = 0; i < 5; i++) t.slots[i] = { kind: 'fixed' }; // bank code + '0'
  return t;
}

/** E.164 country calling codes that are 1 or 2 digits long (everything else is 3). */
const CC1 = new Set(['1', '7']);
const CC2 = new Set([
  '20', '27', '30', '31', '32', '33', '34', '36', '39', '40', '41', '43', '44', '45', '46', '47', '48', '49',
  '51', '52', '53', '54', '55', '56', '57', '58', '60', '61', '62', '63', '64', '65', '66', '81', '82', '84',
  '86', '90', '91', '92', '93', '94', '95', '98',
]);

function phoneTemplate(value: string, region?: string): Template | null {
  const chars = Array.from(value);
  const d = positions(chars, /\d/);
  const digits = d.map((p) => chars[p]).join('');
  const slots = fixedSlots(chars.length);
  let keep = 0;
  let cc = '';
  if (value.trim().startsWith('+')) {
    if (CC1.has(digits.slice(0, 1))) keep = 1;
    else if (CC2.has(digits.slice(0, 2))) keep = 2;
    else keep = 3;
    cc = digits.slice(0, keep);
  } else if (digits[0] === '0') {
    keep = 1; // trunk prefix
  }
  const national = d.slice(keep);
  if (national.length < 6) return null;
  const isIndianMobile =
    (cc === '91' || region === 'IN') && national.length === 10 && /[6-9]/.test(chars[national[0] as number] ?? '');
  const isNanp = cc === '1' || region === 'NANP';
  national.forEach((p, i) => {
    if (isIndianMobile && i === 0) slots[p] = { kind: 'var', alphabet: '6789' };
    else if (isNanp && national.length === 10 && (i === 0 || i === 3)) slots[p] = { kind: 'var', alphabet: '23456789' };
    else if (!isIndianMobile && !isNanp && i === 0) slots[p] = { kind: 'fixed' };
    else slots[p] = { kind: 'var', alphabet: DIGITS };
  });
  return { chars, slots };
}

function tweakFor(seed: string, type: string): Uint8Array {
  return createHash('sha256').update(`vela-fpe-tweak-v1|${seed}|${type}`).digest().subarray(0, 16);
}

/**
 * Format-preserving masker built on NIST FF1.
 *
 * Every structured entity is encoded as a mixed-radix integer over its variable
 * positions, encrypted with FF1 (radix 10) and cycle-walked back into the valid
 * domain. The result keeps length, separators, character classes AND structural
 * validity (Verhoeff / Luhn / GSTIN / IBAN check digits are recomputed), and the
 * mapping is a bijection so two different inputs never collide.
 */
export class FpeMasker {
  private readonly ff1: FF1;
  private readonly key: Uint8Array;
  private readonly tweak: Uint8Array;
  private readonly alphabetCiphers = new Map<string, FF1>();

  constructor(key: Uint8Array, tweak: Uint8Array = new Uint8Array(8)) {
    if (key.length !== 32) {
      throw new Error(`FPE key must be exactly 32 bytes, received ${key.length} bytes`);
    }
    this.key = key;
    this.tweak = tweak;
    this.ff1 = new FF1(key, tweak, DIGITS);
  }

  static isStructured(type: EntityType): boolean {
    return STRUCTURED_TYPES.includes(type);
  }

  /**
   * Encrypt a structured entity. Returns null when the type has no handler or the
   * value's domain is too small to encrypt safely (caller must then use a token).
   */
  encryptEntity(type: EntityType, value: string, seed: string, metadata?: Record<string, unknown>): string | null {
    return this.transformEntity(type, value, seed, metadata, true);
  }

  decryptEntity(type: EntityType, value: string, seed: string, metadata?: Record<string, unknown>): string | null {
    return this.transformEntity(type, value, seed, metadata, false);
  }

  /**
   * Generic character-class-preserving encryption (backwards-compatible API).
   * Returns null if the value's domain is below the NIST minimum.
   */
  encrypt(value: string, explicitAlphabet?: string): string | null {
    if (explicitAlphabet) return this.legacyAlphabet(value, explicitAlphabet, true);
    return this.runTemplate(genericTemplate(value), this.tweak, true);
  }

  decrypt(ciphertext: string, explicitAlphabet?: string): string | null {
    if (explicitAlphabet) return this.legacyAlphabet(ciphertext, explicitAlphabet, false);
    return this.runTemplate(genericTemplate(ciphertext), this.tweak, false);
  }

  private transformEntity(
    type: EntityType,
    value: string,
    seed: string,
    metadata: Record<string, unknown> | undefined,
    enc: boolean,
  ): string | null {
    const tweak = tweakFor(seed, type);
    try {
      switch (type) {
        case 'AADHAAR':
          return this.runTemplate(aadhaarTemplate(value), tweak, enc);
        case 'CREDIT_CARD':
          return this.runTemplate(cardTemplate(value), tweak, enc);
        case 'PAN':
          return this.runTemplate(panTemplate(value), tweak, enc);
        case 'GSTIN':
          return this.gstin(value, seed, enc);
        case 'PHONE':
          return this.runTemplate(phoneTemplate(value, metadata?.['region'] as string | undefined), tweak, enc);
        case 'SSN':
          return this.runTemplate(ssnTemplate(value), tweak, enc);
        case 'IBAN':
          return this.runTemplate(ibanTemplate(value), tweak, enc);
        case 'IFSC':
          return this.runTemplate(ifscTemplate(value), tweak, enc);
        case 'IP_ADDRESS':
          return this.ipv4(value, tweak, enc);
        case 'BANK_ACCOUNT':
        case 'PASSPORT':
          return this.runTemplate(genericTemplate(value), tweak, enc);
        default:
          return null;
      }
    } catch {
      return null;
    }
  }

  /** GSTIN = state code + PAN + entity code + 'Z' + check char. The embedded PAN is masked
   *  exactly like a standalone PAN so the two stay consistent within a session. */
  private gstin(value: string, seed: string, enc: boolean): string | null {
    if (value.length !== 15) return null;
    const pan = this.transformEntity('PAN', value.slice(2, 12), seed, undefined, enc);
    if (!pan) return null;
    const body = value.slice(0, 2) + pan + value.slice(12, 14);
    const check = gstinCheckChar(body.toUpperCase());
    return body + check;
  }

  private ipv4(value: string, tweak: Uint8Array, enc: boolean): string | null {
    const parts = value.split('.');
    if (parts.length !== 4) return null;
    let x = 0n;
    for (const p of parts) {
      const n = Number(p);
      if (!/^\d{1,3}$/.test(p) || n > 255) return null;
      x = x * 256n + BigInt(n);
    }
    const y = this.walk(x, 1n << 32n, tweak, enc);
    const out: number[] = [];
    let v = y;
    for (let i = 0; i < 4; i++) {
      out.unshift(Number(v & 0xffn));
      v >>= 8n;
    }
    return out.join('.');
  }

  /** Cycle-walking FF1 permutation over [0, N). */
  private walk(x: bigint, N: bigint, tweak: Uint8Array, enc: boolean, accept?: (v: bigint) => boolean): bigint {
    const L = (N - 1n).toString().length;
    let cur = x;
    for (let i = 0; i < MAX_WALK; i++) {
      const s = cur.toString().padStart(L, '0');
      cur = BigInt(enc ? this.ff1.encrypt(s, tweak) : this.ff1.decrypt(s, tweak));
      if (cur < N && (!accept || accept(cur))) return cur;
    }
    throw new Error('FPE cycle walk did not converge');
  }

  private runTemplate(tpl: Template | null, tweak: Uint8Array, enc: boolean): string | null {
    if (!tpl) return null;
    const varIdx: number[] = [];
    const radices: bigint[] = [];
    for (let i = 0; i < tpl.slots.length; i++) {
      const s = tpl.slots[i] as Slot;
      if (s.kind === 'var') {
        if (!s.alphabet.includes(tpl.chars[i] as string)) return null;
        varIdx.push(i);
        radices.push(BigInt(s.alphabet.length));
      }
    }
    const N = radices.reduce((a, b) => a * b, 1n);
    if (N < MIN_DOMAIN) return null;

    const encode = (chars: string[]): bigint => {
      let x = 0n;
      varIdx.forEach((p, k) => {
        const s = tpl.slots[p] as { alphabet: string };
        x = x * (radices[k] as bigint) + BigInt(s.alphabet.indexOf(chars[p] as string));
      });
      return x;
    };
    const decode = (x: bigint): string[] => {
      const chars = [...tpl.chars];
      for (let k = varIdx.length - 1; k >= 0; k--) {
        const p = varIdx[k] as number;
        const r = radices[k] as bigint;
        const s = tpl.slots[p] as { alphabet: string };
        chars[p] = s.alphabet[Number(x % r)] as string;
        x /= r;
      }
      tpl.finalize?.(chars);
      return chars;
    };

    // Only constrain the walk if the input itself satisfies the constraint (keeps it a bijection).
    const useAccept = tpl.accept && tpl.accept(tpl.chars) ? tpl.accept : undefined;
    const y = this.walk(encode(tpl.chars), N, tweak, enc, useAccept ? (v) => useAccept(decode(v)) : undefined);
    return decode(y).join('');
  }

  private legacyAlphabet(value: string, alphabet: string, enc: boolean): string | null {
    let f = this.alphabetCiphers.get(alphabet);
    if (!f) {
      f = new FF1(this.key, this.tweak, alphabet);
      this.alphabetCiphers.set(alphabet, f);
    }
    const coreIdx = positions(Array.from(value), /[0-9A-Za-z]/);
    const chars = Array.from(value);
    const core = coreIdx.map((p) => chars[p]).join('');
    try {
      const out = enc ? f.encrypt(core) : f.decrypt(core);
      coreIdx.forEach((p, k) => (chars[p] = out[k] as string));
      return chars.join('');
    } catch {
      return null;
    }
  }
}
