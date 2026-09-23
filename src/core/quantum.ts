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
 * Vela quantum-resilient key management.
 * Uses ML-KEM-768 (NIST FIPS 203) for post-quantum key agreement and
 * AES-256-GCM to protect FPE keys in transit.
 */
export class QuantumKeyManager {
  /**
   * Generate an ML-KEM-768 keypair.
   * The public key can be safely shared over untrusted networks.
   * The secret key must remain local.
   */
  static generateKeyPair(): KeyPair {
    const kp = ml_kem768.keygen();
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
    const res = ml_kem768.encapsulate(peerPublicKey);
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
   * Seal (encrypt) an FPE key using AES-256-GCM with a post-quantum shared secret.
   */
  static sealFpeKey(fpeKey: Uint8Array, sharedSecret: Uint8Array): SealedKey {
    if (fpeKey.length !== 32) {
      throw new Error(`FPE key must be 32 bytes, received ${fpeKey.length}`);
    }
    if (sharedSecret.length !== 32) {
      throw new Error(`Shared secret must be 32 bytes, received ${sharedSecret.length}`);
    }

    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', sharedSecret, iv);
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
  static unsealFpeKey(sealed: SealedKey, sharedSecret: Uint8Array): Uint8Array {
    if (sharedSecret.length !== 32) {
      throw new Error(`Shared secret must be 32 bytes, received ${sharedSecret.length}`);
    }

    const decipher = createDecipheriv('aes-256-gcm', sharedSecret, sealed.iv);
    decipher.setAuthTag(sealed.tag);
    const decrypted = Buffer.concat([decipher.update(sealed.data), decipher.final()]);

    return new Uint8Array(decrypted);
  }
}
