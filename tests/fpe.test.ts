import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FpeMasker } from '../src/core/fpe.js';

describe('FF1 Format-Preserving Encryption (FpeMasker)', () => {
  const key = new Uint8Array(32).fill(7);
  const fpe = new FpeMasker(key);

  it('should preserve numeric format and length', () => {
    const original = '123456789012';
    const encrypted = fpe.encrypt(original);

    assert.ok(encrypted);
    assert.equal(encrypted.length, original.length);
    assert.match(encrypted, /^[0-9]+$/);
    assert.notEqual(encrypted, original);

    const decrypted = fpe.decrypt(encrypted);
    assert.equal(decrypted, original);
  });

  it('should preserve formatting spaces and delimiters', () => {
    const original = '2345 6789 0123';
    const encrypted = fpe.encrypt(original);

    assert.ok(encrypted);
    assert.equal(encrypted.length, original.length);
    assert.equal(encrypted[4], ' ');
    assert.equal(encrypted[9], ' ');

    const decrypted = fpe.decrypt(encrypted);
    assert.equal(decrypted, original);
  });

  it('should preserve alphanumeric characters for PAN format', () => {
    const pan = 'ABCDE1234F';
    const encrypted = fpe.encrypt(pan);

    assert.ok(encrypted);
    assert.equal(encrypted.length, pan.length);
    assert.match(encrypted, /^[A-Z0-9]+$/);
    assert.notEqual(encrypted, pan);

    const decrypted = fpe.decrypt(encrypted);
    assert.equal(decrypted, pan);
  });

  it('should handle custom tweaks deterministically', () => {
    const tweak1 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const tweak2 = new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]);

    const fpe1 = new FpeMasker(key, tweak1);
    const fpe2 = new FpeMasker(key, tweak2);

    const input = '9876543210';
    const enc1 = fpe1.encrypt(input);
    const enc2 = fpe2.encrypt(input);

    assert.notEqual(enc1, enc2);
    assert.equal(fpe1.decrypt(enc1!), input);
    assert.equal(fpe2.decrypt(enc2!), input);
  });

  it('should reject invalid keys', () => {
    assert.throws(() => new FpeMasker(new Uint8Array(16)));
  });
});
