/**
 * Key providers: where the 32-byte FF1 key comes from. Use with
 * `await Vela.create({ keyProvider })`; the key id goes into audit events.
 *
 * Restoration uses per-request maps, not decryption, so rotating the key needs
 * no migration: start new instances with the new key. The adapters take your
 * cloud SDK client as an argument (duck-typed), so Vela adds no dependencies.
 */
export interface ProvidedKey {
  key: Uint8Array;
  /** Identifier recorded in audit events (never the key). */
  keyId: string;
}

export interface KeyProvider {
  getKey(): Promise<ProvidedKey>;
}

function check(key: Uint8Array, keyId: string): ProvidedKey {
  if (key.length !== 32) throw new Error(`Key provider returned ${key.length} bytes for ${keyId}; Vela needs exactly 32`);
  return { key, keyId };
}

const toBytes = (v: Uint8Array | string): Uint8Array => (typeof v === 'string' ? new Uint8Array(Buffer.from(v, 'base64')) : new Uint8Array(v));

/** 64 hex characters from an environment variable (default `VELA_FPE_KEY`). */
export function envKeyProvider(name = 'VELA_FPE_KEY', keyId = `env:${name}`): KeyProvider {
  return {
    async getKey() {
      const hex = process.env[name];
      if (!hex || !/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error(`${name} must hold 64 hex characters`);
      return check(new Uint8Array(Buffer.from(hex, 'hex')), keyId);
    },
  };
}

/**
 * Envelope encryption with any KMS: `wrappedKey` is the data key encrypted by
 * the KMS; `unwrap` asks the KMS to decrypt it. The adapters below are thin
 * wrappers around this.
 */
export function envelopeKeyProvider(opts: { wrappedKey: Uint8Array | string; keyId: string; unwrap: (wrapped: Uint8Array) => Promise<Uint8Array> }): KeyProvider {
  return { getKey: async () => check(await opts.unwrap(toBytes(opts.wrappedKey)), opts.keyId) };
}

/**
 * AWS KMS: `kms` is a `KMSClient` and `DecryptCommand` the class from
 * `@aws-sdk/client-kms`. `ciphertextBlob` is the output of `GenerateDataKey`
 * (32-byte AES_256 data key).
 */
export function awsKmsKeyProvider(opts: {
  kms: { send: (cmd: unknown) => Promise<{ Plaintext?: Uint8Array }> };
  DecryptCommand: new (input: { CiphertextBlob: Uint8Array; KeyId?: string }) => unknown;
  ciphertextBlob: Uint8Array | string;
  kmsKeyId: string;
}): KeyProvider {
  return envelopeKeyProvider({
    wrappedKey: opts.ciphertextBlob,
    keyId: `aws-kms:${opts.kmsKeyId}`,
    unwrap: async (blob) => {
      const out = await opts.kms.send(new opts.DecryptCommand({ CiphertextBlob: blob, KeyId: opts.kmsKeyId }));
      if (!out.Plaintext) throw new Error('AWS KMS returned no plaintext');
      return new Uint8Array(out.Plaintext);
    },
  });
}

/** Azure Key Vault: `crypto` is a `CryptographyClient` (`@azure/keyvault-keys`) for an RSA key. */
export function azureKeyVaultKeyProvider(opts: {
  crypto: { unwrapKey: (alg: string, key: Uint8Array) => Promise<{ result: Uint8Array }>; keyID?: string };
  wrappedKey: Uint8Array | string;
  algorithm?: string;
}): KeyProvider {
  return envelopeKeyProvider({
    wrappedKey: opts.wrappedKey,
    keyId: `azure-kv:${opts.crypto.keyID ?? 'key'}`,
    unwrap: async (w) => new Uint8Array((await opts.crypto.unwrapKey(opts.algorithm ?? 'RSA-OAEP-256', w)).result),
  });
}

/** Google Cloud KMS: `kms` is a `KeyManagementServiceClient` (`@google-cloud/kms`); `name` the CryptoKey resource name. */
export function gcpKmsKeyProvider(opts: {
  kms: { decrypt: (req: { name: string; ciphertext: Uint8Array }) => Promise<Array<{ plaintext?: Uint8Array | string | null }>> };
  name: string;
  ciphertext: Uint8Array | string;
}): KeyProvider {
  return envelopeKeyProvider({
    wrappedKey: opts.ciphertext,
    keyId: `gcp-kms:${opts.name}`,
    unwrap: async (c) => {
      const [res] = await opts.kms.decrypt({ name: opts.name, ciphertext: c });
      if (!res?.plaintext) throw new Error('Google Cloud KMS returned no plaintext');
      return toBytes(res.plaintext);
    },
  });
}

/** HashiCorp Vault transit engine over HTTP (no SDK): decrypts `ciphertext` (`vault:v1:…`) with key `keyName`. */
export function vaultTransitKeyProvider(opts: {
  address: string;
  token: string;
  keyName: string;
  ciphertext: string;
  mount?: string;
  namespace?: string;
  fetchImpl?: typeof fetch;
}): KeyProvider {
  const version = /^vault:(v\d+):/.exec(opts.ciphertext)?.[1] ?? 'v?';
  return {
    async getKey() {
      const res = await (opts.fetchImpl ?? fetch)(`${opts.address.replace(/\/+$/, '')}/v1/${opts.mount ?? 'transit'}/decrypt/${encodeURIComponent(opts.keyName)}`, {
        method: 'POST',
        headers: { 'x-vault-token': opts.token, 'content-type': 'application/json', ...(opts.namespace ? { 'x-vault-namespace': opts.namespace } : {}) },
        body: JSON.stringify({ ciphertext: opts.ciphertext }),
      });
      if (!res.ok) throw new Error(`Vault transit decrypt returned HTTP ${res.status}`);
      const body = (await res.json()) as { data?: { plaintext?: string } };
      if (!body.data?.plaintext) throw new Error('Vault transit returned no plaintext');
      return check(toBytes(body.data.plaintext), `vault-transit:${opts.keyName}:${version}`);
    },
  };
}
