/**
 * Key providers (F9 in docs/COMPLIANCE_AUDIT.md). Cloud SDK clients are faked:
 * the adapters are duck-typed so Vela needs no SDK dependency.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  Vela,
  envKeyProvider,
  envelopeKeyProvider,
  awsKmsKeyProvider,
  azureKeyVaultKeyProvider,
  gcpKmsKeyProvider,
  vaultTransitKeyProvider,
} from '../src/index.js';

const KEY = new Uint8Array(32).fill(9);
const WRAPPED = new Uint8Array([1, 2, 3]);

describe('key providers', () => {
  it('env provider reads 64 hex characters', async () => {
    process.env['VELA_TEST_KEY'] = '09'.repeat(32);
    const k = await envKeyProvider('VELA_TEST_KEY').getKey();
    assert.deepEqual(k, { key: KEY, keyId: 'env:VELA_TEST_KEY' });
    process.env['VELA_TEST_KEY'] = 'short';
    await assert.rejects(envKeyProvider('VELA_TEST_KEY').getKey(), /64 hex/);
  });

  it('rejects keys that are not 32 bytes', async () => {
    await assert.rejects(envelopeKeyProvider({ wrappedKey: WRAPPED, keyId: 'k', unwrap: async () => new Uint8Array(16) }).getKey(), /exactly 32/);
  });

  it('AWS, Azure and GCP adapters call their clients', async () => {
    class DecryptCommand {
      constructor(readonly input: { CiphertextBlob: Uint8Array }) {}
    }
    const aws = awsKmsKeyProvider({
      kms: { send: async (cmd) => (assert.deepEqual((cmd as DecryptCommand).input.CiphertextBlob, WRAPPED), { Plaintext: KEY }) },
      DecryptCommand,
      ciphertextBlob: WRAPPED,
      kmsKeyId: 'alias/vela',
    });
    assert.equal((await aws.getKey()).keyId, 'aws-kms:alias/vela');
    const azure = azureKeyVaultKeyProvider({ crypto: { keyID: 'https://kv/keys/vela/1', unwrapKey: async () => ({ result: KEY }) }, wrappedKey: WRAPPED });
    assert.equal((await azure.getKey()).keyId, 'azure-kv:https://kv/keys/vela/1');
    const gcp = gcpKmsKeyProvider({ kms: { decrypt: async () => [{ plaintext: Buffer.from(KEY).toString('base64') }] }, name: 'projects/p/keyRings/r/cryptoKeys/vela', ciphertext: WRAPPED });
    assert.deepEqual((await gcp.getKey()).key, KEY);
  });

  it('Vault transit adapter decrypts over HTTP', async () => {
    let seen: { url: string; token: string | null; body: string } | undefined;
    const fetchImpl = (async (url: string, init: RequestInit) => {
      seen = { url, token: new Headers(init.headers).get('x-vault-token'), body: String(init.body) };
      return new Response(JSON.stringify({ data: { plaintext: Buffer.from(KEY).toString('base64') } }), { status: 200 });
    }) as unknown as typeof fetch;
    const p = vaultTransitKeyProvider({ address: 'http://vault:8200/', token: 't0k', keyName: 'vela', ciphertext: 'vault:v3:abc', fetchImpl });
    const k = await p.getKey();
    assert.equal(k.keyId, 'vault-transit:vela:v3');
    assert.equal(seen?.url, 'http://vault:8200/v1/transit/decrypt/vela');
    assert.equal(seen?.token, 't0k');
  });

  it('Vela.create uses the key and records its id', async () => {
    const vela = await Vela.create({ keyProvider: envelopeKeyProvider({ wrappedKey: WRAPPED, keyId: 'kms:x/7', unwrap: async () => KEY }) });
    assert.equal(vela.auditContext.key_id, 'kms:x/7');
    const same = new Vela({ fpeKey: KEY });
    const a = vela.createSession({ sessionId: 's' }).mask('PAN ABCDE1234F');
    const b = same.createSession({ sessionId: 's' }).mask('PAN ABCDE1234F');
    assert.equal(a, b);
  });
});
