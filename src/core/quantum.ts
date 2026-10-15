import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';

export interface SealedKey {
  iv: Uint8Array;
  tag: Uint8Array;
  data: Uint8Array;
}

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface EncapsulationResult {
  cipherText: Uint8Array;
  sharedSecret: Uint8Array;
}

/**
 * Key management for distributing a shared FPE key between services.
 *
 * ML-KEM-768 (NIST FIPS 203) provides post-quantum key agreement and
 * AES-256-GCM protects the FPE key in transit. You only need this when several
 * processes/hosts must share one FPE key (e.g. a stable `sessionId` across a
 * cluster); a single process can simply use a random 32-byte key.
 */
export class QuantumKeyManager {
  /**
   * Generate an ML-KEM-768 keypair.
   * The public key can be safely shared over untrusted networks.
   * The secret key must remain local.
   */
  static generateKeyPair(): KeyPair {
    // Randomness from node:crypto: @noble falls back to globalThis.crypto,
    // which Node 18 does not expose by default.
    const kp = ml_kem768.keygen(new Uint8Array(randomBytes(ml_kem768.lengths.seed ?? 64)));
    return {
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
    };
  }

  /**
   * Encapsulate a shared secret to a peer's ML-KEM-768 public key.
   * Returns ciphertext (to transmit) and 32-byte shared secret (to use locally).
   */
  static encapsulate(peerPublicKey: Uint8Array): EncapsulationResult {
    const res = ml_kem768.encapsulate(peerPublicKey, new Uint8Array(randomBytes(ml_kem768.lengths.msgRand ?? 32)));
    return {
      cipherText: res.cipherText,
      sharedSecret: res.sharedSecret,
    };
  }

  /**
   * Decapsulate the shared secret from a received ciphertext using own secret key.
   */
  static decapsulate(ciphertext: Uint8Array, ownSecretKey: Uint8Array): Uint8Array {
    return ml_kem768.decapsulate(ciphertext, ownSecretKey);
  }

  /**
   * Derive a stable 32-byte FPE key from a shared secret using HKDF-SHA256.
   */
  static deriveFpeKey(sharedSecret: Uint8Array, salt?: Uint8Array, infoStr = 'vela-fpe-key-v1'): Uint8Array {
    // HKDF-Extract
    const extract = createHmac('sha256', salt ?? new Uint8Array(32));
    extract.update(sharedSecret);
    const prk = extract.digest();

    // HKDF-Expand
    const info = Buffer.from(infoStr);
    const expand = createHmac('sha256', prk);
    expand.update(info);
    expand.update(Buffer.from([1]));
    const derived = expand.digest();

    return new Uint8Array(derived.subarray(0, 32));
  }

  /**
   * Seal (encrypt) an FPE key for transport using AES-256-GCM.
   * The AES key is HKDF-derived from the ML-KEM shared secret with its own label
   * ("vela-seal-key-v1"), so it never equals a key derived for FPE from the same
   * secret. Optional `aad` binds the sealed blob to context (e.g. tenant id).
   */
  static sealFpeKey(fpeKey: Uint8Array, sharedSecret: Uint8Array, aad?: Uint8Array): SealedKey {
    if (fpeKey.length !== 32) {
      throw new Error(`FPE key must be 32 bytes, received ${fpeKey.length}`);
    }
    if (sharedSecret.length !== 32) {
      throw new Error(`Shared secret must be 32 bytes, received ${sharedSecret.length}`);
    }

    const iv = randomBytes(12);
    const sealKey = QuantumKeyManager.deriveFpeKey(sharedSecret, undefined, 'vela-seal-key-v1');
    const cipher = createCipheriv('aes-256-gcm', sealKey, iv);
    if (aad) cipher.setAAD(aad);
    const data = Buffer.concat([cipher.update(fpeKey), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      iv: new Uint8Array(iv),
      tag: new Uint8Array(tag),
      data: new Uint8Array(data),
    };
  }

  /**
   * Unseal (decrypt) an FPE key using AES-256-GCM with a post-quantum shared secret.
   */
  static unsealFpeKey(sealed: SealedKey, sharedSecret: Uint8Array, aad?: Uint8Array): Uint8Array {
    if (sharedSecret.length !== 32) {
      throw new Error(`Shared secret must be 32 bytes, received ${sharedSecret.length}`);
    }

    const sealKey = QuantumKeyManager.deriveFpeKey(sharedSecret, undefined, 'vela-seal-key-v1');
    const decipher = createDecipheriv('aes-256-gcm', sealKey, sealed.iv);
    if (aad) decipher.setAAD(aad);
    decipher.setAuthTag(sealed.tag);
    const decrypted = Buffer.concat([decipher.update(sealed.data), decipher.final()]);

    return new Uint8Array(decrypted);
  }
}
