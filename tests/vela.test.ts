import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Vela } from '../src/core/vela.js';
import { QuantumKeyManager } from '../src/core/quantum.js';
import { generateVerhoeffChecksum } from '../src/core/algorithms/verhoeff.js';

describe('Vela Privacy Engine Pipeline', () => {
  const kp = QuantumKeyManager.generateKeyPair();
  const { sharedSecret } = QuantumKeyManager.encapsulate(kp.publicKey);
  const fpeKey = QuantumKeyManager.deriveFpeKey(sharedSecret);

  const base = '23456789012';
  const chk = generateVerhoeffChecksum(base);
  const validAadhaar = `${base.slice(0, 4)} ${base.slice(4, 8)} ${base.slice(8, 11)}${chk}`;

  it('should mask structured IDs with FPE and soft PII with tokens', () => {
    const vela = new Vela({
      fpeKey,
      glossary: ['ProjectVela'],
    });

    const input = `User with PAN ABCDE1234F and Aadhaar ${validAadhaar} has email alice@example.com working on ProjectVela.`;
    const masked = vela.mask(input);

    // FPE preservation checks
    assert.doesNotMatch(masked.text, /ABCDE1234F/);
    assert.doesNotMatch(masked.text, new RegExp(validAadhaar));

    // Token replacement checks
    assert.match(masked.text, /<PII type="EMAIL" id="\d+"\/>/);
    assert.match(masked.text, /<PII type="CUSTOM" id="\d+"\/>/);

    // Round-trip unmasking
    const unmasked = vela.unmask(masked.text, masked);
    assert.equal(unmasked.text, input);
    assert.equal(unmasked.restored, 4);
  });

  it('should unmask LLM responses that repeat masked values', () => {
    const vela = new Vela({ fpeKey });
    const prompt = `Review PAN ABCDE1234F and email user@org.in.`;
    const masked = vela.mask(prompt);

    // Simulate LLM response referencing the masked tokens
    const llmResponse = `Received application for ${Object.keys(masked.mapping)[0]} with tax identifier ${Object.values(masked.fpeMap)[0]}. Approved.`;
    const unmasked = vela.unmask(llmResponse, masked);

    assert.match(unmasked.text, /user@org\.in/);
    assert.match(unmasked.text, /ABCDE1234F/);
    assert.equal(unmasked.restored, 2);
  });

  it('should auto-derive an ephemeral quantum key when fpeKey is omitted', () => {
    const autoVela = new Vela();
    const masked = autoVela.mask('User email is test@domain.com');
    assert.match(masked.text, /<PII type="EMAIL" id="\d+"\/>/);

    const unmasked = autoVela.unmask(masked.text, masked);
    assert.equal(unmasked.text, 'User email is test@domain.com');
  });

  it('should isolate token IDs across independent mask calls to avoid session bleed', () => {
    const sessionVela = new Vela();
    const mask1 = sessionVela.mask('Email 1 is first@domain.com');
    const mask2 = sessionVela.mask('Email 2 is second@domain.com');

    // Both independent calls should start at id="0" for their first token
    assert.ok(mask1.mapping['<PII type="EMAIL" id="0"/>']);
    assert.ok(mask2.mapping['<PII type="EMAIL" id="0"/>']);

    // Neither should bleed mapping into the other
    assert.equal(Object.keys(mask1.mapping).length, 1);
    assert.equal(Object.keys(mask2.mapping).length, 1);
  });
});
