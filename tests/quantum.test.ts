import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { QuantumKeyManager } from '../src/core/quantum.js';

describe('QuantumKeyManager (ML-KEM-768 & AES-256-GCM)', () => {
  it('should generate valid keypair and establish quantum-resilient shared secret', () => {
    // 1. Bob generates ML-KEM-768 keypair
    const bob = QuantumKeyManager.generateKeyPair();
    assert.ok(bob.publicKey.length > 0);
    assert.ok(bob.secretKey.length > 0);

    // 2. Alice encapsulates a shared secret using Bob's public key
    const { cipherText, sharedSecret: aliceSecret } = QuantumKeyManager.encapsulate(bob.publicKey);
    assert.equal(aliceSecret.length, 32);

    // 3. Bob decapsulates the shared secret using his secret key
    const bobSecret = QuantumKeyManager.decapsulate(cipherText, bob.secretKey);
    assert.equal(bobSecret.length, 32);

    // 4. Both shared secrets must match exactly
    assert.deepEqual(aliceSecret, bobSecret);

    // 5. Both derive identical FPE keys
    const aliceFpeKey = QuantumKeyManager.deriveFpeKey(aliceSecret);
    const bobFpeKey = QuantumKeyManager.deriveFpeKey(bobSecret);
    assert.equal(aliceFpeKey.length, 32);
    assert.deepEqual(aliceFpeKey, bobFpeKey);
  });

  it('should seal and unseal FPE keys with AES-256-GCM', () => {
    const secret = new Uint8Array(32).fill(42);
    const fpeKey = new Uint8Array(32).fill(99);

    const sealed = QuantumKeyManager.sealFpeKey(fpeKey, secret);
    assert.equal(sealed.iv.length, 12);
    assert.equal(sealed.tag.length, 16);
    assert.equal(sealed.data.length, 32);

    const unsealed = QuantumKeyManager.unsealFpeKey(sealed, secret);
    assert.deepEqual(unsealed, fpeKey);
  });

  it('should fail unsealing with corrupted tag or data', () => {
    const secret = new Uint8Array(32).fill(42);
    const fpeKey = new Uint8Array(32).fill(99);

    const sealed = QuantumKeyManager.sealFpeKey(fpeKey, secret);
    const tampered = {
      ...sealed,
      data: new Uint8Array(sealed.data),
    };
    tampered.data[0] = (tampered.data[0] ?? 0) ^ 0xff;

    assert.throws(() => QuantumKeyManager.unsealFpeKey(tampered, secret));
  });
});
