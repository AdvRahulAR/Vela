import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateVerhoeff, generateVerhoeffChecksum } from '../src/core/algorithms/verhoeff.js';

describe('Verhoeff Checksum Algorithm', () => {
  it('should generate valid checksum for 11-digit numbers', () => {
    const base = '23456789012';
    const checksum = generateVerhoeffChecksum(base);
    const fullAadhaar = base + checksum.toString();

    assert.equal(validateVerhoeff(fullAadhaar), true);
  });

  it('should validate Aadhaar with spaced format', () => {
    const base = '39124567890';
    const checksum = generateVerhoeffChecksum(base);
    const full = `${base.slice(0, 4)} ${base.slice(4, 8)} ${base.slice(8, 11)}${checksum}`;

    assert.equal(validateVerhoeff(full), true);
  });

  it('should reject invalid checksums', () => {
    // 23456789012 with incorrect last digit
    assert.equal(validateVerhoeff('234567890120'), false);
    assert.equal(validateVerhoeff('234567890121'), false);
  });

  it('should reject numbers starting with 0 or 1', () => {
    assert.equal(validateVerhoeff('012345678901'), false);
    assert.equal(validateVerhoeff('123456789012'), false);
  });

  it('should reject invalid lengths', () => {
    assert.equal(validateVerhoeff('2345678901'), false);
    assert.equal(validateVerhoeff('2345678901234'), false);
    assert.equal(validateVerhoeff(''), false);
  });
});
