import { createFF1 } from 'ff1-js';
import { DIGITS, LOWER_ALNUM, MIXED_ALNUM, UPPER_ALNUM, DEFAULT_TWEAK } from '../config/constants.js';
import type { EntityType } from '../types.js';

interface FF1Cipher {
  encrypt: (plaintext: string) => string;
  decrypt: (ciphertext: string) => string;
}

/**
 * Vela FPE (Format-Preserving Encryption) masker.
 * Uses NIST SP 800-38G FF1 to encrypt structured identifiers (Aadhaar, PAN,
 * GSTIN, Credit Cards, phone numbers, case IDs) preserving exact format and charset.
 */
export class FpeMasker {
  private key: Uint8Array;
  private tweak: Uint8Array;
  private ciphers: Map<string, FF1Cipher> = new Map();

  constructor(key: Uint8Array, tweak: Uint8Array = DEFAULT_TWEAK) {
    if (key.length !== 32) {
      throw new Error(`FPE key must be exactly 32 bytes, received ${key.length} bytes`);
    }
    this.key = key;
    this.tweak = tweak;
  }

  /**
   * Lazily create and cache an FF1 cipher instance for a given alphabet.
   */
  private cipherFor(alphabet: string): FF1Cipher {
    let cipher = this.ciphers.get(alphabet);
    if (!cipher) {
      cipher = createFF1(Buffer.from(this.key), Buffer.from(this.tweak), alphabet) as FF1Cipher;
      this.ciphers.set(alphabet, cipher);
    }
    return cipher;
  }

  /**
   * Select alphabet that matches the character set of the core string.
   */
  private alphabetFor(value: string): string {
    if (/^[0-9]+$/.test(value)) return DIGITS;
    if (/^[A-Z0-9]+$/.test(value)) return UPPER_ALNUM;
    if (/^[a-z0-9]+$/.test(value)) return LOWER_ALNUM;
    return MIXED_ALNUM;
  }

  /**
   * Encrypt a value preserving its format, separators, and character set.
   * Returns null if value is unsupported or below minimum FF1 length.
   */
  encrypt(value: string, explicitAlphabet?: string): string | null {
    if (value.length < 2 || value.length > 100) return null;

    const core = value.replace(/[^0-9A-Za-z]/g, '');
    if (core.length < 2) return null;

    const alphabet = explicitAlphabet ?? this.alphabetFor(core);

    try {
      const cipher = this.cipherFor(alphabet);
      const cipherCore = cipher.encrypt(core);

      let result = '';
      let ci = 0;
      for (let i = 0; i < value.length; i++) {
        const char = value[i];
        if (char === undefined) continue;
        if (/[^0-9A-Za-z]/.test(char)) {
          result += char;
        } else {
          result += cipherCore[ci++];
        }
      }
      return result;
    } catch {
      return null;
    }
  }

  /**
   * Decrypt an FPE ciphertext back to the original value.
   */
  decrypt(ciphertext: string, explicitAlphabet?: string): string | null {
    if (ciphertext.length < 2 || ciphertext.length > 100) return null;

    const core = ciphertext.replace(/[^0-9A-Za-z]/g, '');
    if (core.length < 2) return null;

    const alphabet = explicitAlphabet ?? this.alphabetFor(core);

    try {
      const cipher = this.cipherFor(alphabet);
      const plainCore = cipher.decrypt(core);

      let result = '';
      let ci = 0;
      for (let i = 0; i < ciphertext.length; i++) {
        const char = ciphertext[i];
        if (char === undefined) continue;
        if (/[^0-9A-Za-z]/.test(char)) {
          result += char;
        } else {
          result += plainCore[ci++];
        }
      }
      return result;
    } catch {
      return null;
    }
  }

  /**
   * Determines if the entity type should be processed by FPE.
   */
  static isStructured(type: EntityType): boolean {
    return [
      'AADHAAR',
      'PAN',
      'GSTIN',
      'CREDIT_CARD',
      'PHONE',
      'SSN',
      'IBAN',
      'IP_ADDRESS',
      'CASE_ID',
    ].includes(type);
  }
}
