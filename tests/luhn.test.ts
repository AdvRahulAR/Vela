import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateLuhn } from '../src/core/algorithms/luhn.js';

describe('Luhn Algorithm', () => {
  it('should validate valid card numbers', () => {
    // Standard test card numbers (Luhn valid)
    assert.equal(validateLuhn('4532015112830366'), true);
    assert.equal(validateLuhn('4532 0151 1283 0366'), true);
    assert.equal(validateLuhn('4532-0151-1283-0366'), true);
  });

  it('should reject invalid card numbers', () => {
    assert.equal(validateLuhn('4532015112830367'), false);
    assert.equal(validateLuhn('1234567812345671'), false);
  });

  it('should reject invalid length strings', () => {
    assert.equal(validateLuhn('12345'), false);
    assert.equal(validateLuhn(''), false);
  });
});
