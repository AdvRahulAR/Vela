import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectPii } from '../src/core/detector.js';
import { generateVerhoeffChecksum } from '../src/core/algorithms/verhoeff.js';

describe('PII Detector', () => {
  it('should detect valid PAN numbers', () => {
    const text = 'User PAN is ABCDE1234F and company PAN is AAACA1111B.';
    const entities = detectPii(text);

    assert.equal(entities.length, 2);
    assert.equal(entities[0]?.type, 'PAN');
    assert.equal(entities[0]?.value, 'ABCDE1234F');
    assert.equal(entities[1]?.type, 'PAN');
    assert.equal(entities[1]?.value, 'AAACA1111B');
  });

  it('should detect valid GSTIN with valid state code', () => {
    const text = 'Invoice GSTIN: 27ABCDE1234F1Z5 for Maharashtra entity.';
    const entities = detectPii(text);

    assert.equal(entities.length, 1);
    assert.equal(entities[0]?.type, 'GSTIN');
    assert.equal(entities[0]?.value, '27ABCDE1234F1Z5');
  });

  it('should reject invalid GSTIN state codes', () => {
    // 00 is not a valid Indian state code
    const text = 'Invalid GSTIN: 00ABCDE1234F1Z5.';
    const entities = detectPii(text);

    assert.equal(entities.length, 0);
  });

  it('should detect valid Aadhaar with Verhoeff verification', () => {
    const base = '23456789012';
    const chk = generateVerhoeffChecksum(base);
    const validAadhaar = `${base.slice(0, 4)} ${base.slice(4, 8)} ${base.slice(8, 11)}${chk}`;

    const text = `Resident Aadhaar is ${validAadhaar}.`;
    const entities = detectPii(text);

    assert.equal(entities.length, 1);
    assert.equal(entities[0]?.type, 'AADHAAR');
    assert.equal(entities[0]?.value, validAadhaar);
  });

  it('should reject random 12-digit numbers as Aadhaar when checksum fails', () => {
    const text = 'Call reference 2345 6789 0120 or random 3333 4444 5550.';
    const entities = detectPii(text);

    // If neither passes Verhoeff, AADHAAR should not be detected
    const aadhaarMatches = entities.filter((e) => e.type === 'AADHAAR');
    assert.equal(aadhaarMatches.length, 0);
  });

  it('should detect Emails and Phones', () => {
    const text = 'Contact support@vela-privacy.io or call +91 9876543210.';
    const entities = detectPii(text);

    const email = entities.find((e) => e.type === 'EMAIL');
    const phone = entities.find((e) => e.type === 'PHONE');

    assert.ok(email);
    assert.equal(email?.value, 'support@vela-privacy.io');
    assert.ok(phone);
    assert.equal(phone?.value, '+91 9876543210');
  });

  it('should detect Indian phone numbers in E.164, spaced, and dashed formats', () => {
    const testCases = [
      { text: 'Reach out on +919876543210 today.', expected: '+919876543210' },
      { text: 'Reach out on +91 98765 43210 today.', expected: '+91 98765 43210' },
      { text: 'Reach out on +91-98765-43210 today.', expected: '+91-98765-43210' },
    ];

    for (const { text, expected } of testCases) {
      const entities = detectPii(text);
      const phone = entities.find((e) => e.type === 'PHONE');
      assert.ok(phone, `Failed to detect phone in: "${text}"`);
      assert.equal(phone?.value, expected);
    }
  });

  it('should reject arbitrary spaced digit strings that are not phone numbers', () => {
    const text = 'Invoice 12345 67890 and batch 98765 43210 or 19876543210.';
    const entities = detectPii(text);
    const phones = entities.filter((e) => e.type === 'PHONE');
    assert.equal(phones.length, 0);
  });

  it('should detect API keys and secrets', () => {
    const text = 'Do not commit sk-proj-12345678901234567890 or AKIAIOSFODNN7EXAMPLE.';
    const entities = detectPii(text);

    const secrets = entities.filter((e) => e.type === 'SECRET_KEY');
    assert.equal(secrets.length, 2);
  });

  it('should fully detect OpenAI (sk-proj-), Anthropic (sk-ant-), and GitHub (ghp_) keys', () => {
    const openAiKey = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx';
    const anthropicKey = 'sk-ant-api03-abcdef1234567890abcdefghijklmnopqrstuvwxyz';
    const githubKey = 'ghp_1234567890abcdefghijklmnopqrstuvwxyzAB';
    const awsKey = 'AKIAIOSFODNN7EXAMPLE';

    const text = `Keys: OpenAI=${openAiKey}, Anthropic=${anthropicKey}, GitHub=${githubKey}, AWS=${awsKey}`;
    const entities = detectPii(text);
    const secrets = entities.filter((e) => e.type === 'SECRET_KEY');

    assert.equal(secrets.length, 4);

    const foundOpenAi = secrets.find((s) => s.value === openAiKey);
    const foundAnthropic = secrets.find((s) => s.value === anthropicKey);
    const foundGitHub = secrets.find((s) => s.value === githubKey);
    const foundAws = secrets.find((s) => s.value === awsKey);

    assert.ok(foundOpenAi, 'Failed to detect OpenAI sk-proj- key');
    assert.ok(foundAnthropic, 'Failed to detect Anthropic sk-ant- key');
    assert.ok(foundGitHub, 'Failed to detect GitHub ghp_ key');
    assert.ok(foundAws, 'Failed to detect AWS key');
  });

  it('should detect Indian court Case IDs', () => {
    const text = 'In CIVIL APPEAL NO. 1234 OF 2020 and WRIT PETITION 45 OF 2019.';
    const entities = detectPii(text);

    const cases = entities.filter((e) => e.type === 'CASE_ID');
    assert.equal(cases.length, 2);
  });

  it('should detect valid IBAN and reject invalid IBAN', () => {
    // Valid German IBAN
    const textValid = 'Wire funds to DE89370400440532013000.';
    const entitiesValid = detectPii(textValid);
    assert.equal(entitiesValid.length, 1);
    assert.equal(entitiesValid[0]?.type, 'IBAN');
    assert.equal(entitiesValid[0]?.value, 'DE89370400440532013000');

    // Invalid check digits
    const textInvalid = 'Wire funds to DE89370400440532013001.';
    const entitiesInvalid = detectPii(textInvalid);
    assert.equal(entitiesInvalid.length, 0);
  });

  it('should bypass checksum validation when validateChecksums is false', () => {
    const invalidAadhaar = '2345 6789 0120';
    const text = `Resident Aadhaar is ${invalidAadhaar}.`;

    const withoutValidation = detectPii(text, { validateChecksums: false });
    const aadhaarMatches = withoutValidation.filter((e) => e.type === 'AADHAAR');
    assert.equal(aadhaarMatches.length, 1);
  });
});
