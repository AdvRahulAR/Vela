/**
 * Policy layer (F4) and synthetic-safe FPE (F7) in docs/COMPLIANCE_AUDIT.md.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  Vela,
  runProxy,
  loadPolicy,
  policyHash,
  validatePolicy,
  POLICY_PRESETS,
  resolvePolicy,
  validateVerhoeff,
  validateLuhn,
  validateGstin,
  validateIban,
  VelaPolicyBlockedError,
  type AuditEvent,
} from '../src/index.js';
import { SENTINELS, SENTINEL_TEXT, assertNoSentinel, startUpstream, baseUrlOf } from './helpers/leak-oracle.js';

const dir = mkdtempSync(join(tmpdir(), 'vela-policy-'));

describe('policy files', () => {
  it('JSON and YAML forms of one policy hash the same', () => {
    writeFileSync(join(dir, 'p.json'), JSON.stringify({ id: 'bank', version: 2, entities: { CREDIT_CARD: 'block', EMAIL: { action: 'redact' } }, nonText: 'block' }));
    writeFileSync(join(dir, 'p.yaml'), 'id: bank\nversion: 2\nnonText: block\nentities:\n  EMAIL:\n    action: redact\n  CREDIT_CARD: block\n');
    const a = loadPolicy(join(dir, 'p.json'));
    const b = loadPolicy(join(dir, 'p.yaml'));
    assert.deepEqual(a, b);
    assert.equal(policyHash(a), policyHash(b));
    assert.match(policyHash(a), /^sha256:[0-9a-f]{64}$/);
  });

  it('rejects typos instead of ignoring them', () => {
    assert.throws(() => validatePolicy({ id: 'x', entitys: {} }), /unknown key "entitys"/);
    assert.throws(() => validatePolicy({ id: 'x', entities: { EMAIL: 'mask' } }), /action must be one of/);
    assert.throws(() => validatePolicy({ id: 'x', restore: { toolArgs: 'placeholders' } }), /unknown key "restore.toolArgs"/);
    writeFileSync(join(dir, 'dup.yaml'), 'id: x\nid: y\n');
    assert.throws(() => loadPolicy(join(dir, 'dup.yaml')), /could not parse/);
  });

  it('every preset validates, constructs and resolves by name', () => {
    for (const name of Object.keys(POLICY_PRESETS)) {
      const p = resolvePolicy(name);
      assert.equal(p.id, name);
      new Vela({ policy: p });
    }
    assert.throws(() => resolvePolicy('no-such-preset'), /No policy preset or file/);
  });

  it('ner.required refuses to start without an NER service', () => {
    assert.throws(() => new Vela({ policy: { id: 'x', ner: { required: true } } }), /requires an NER service/);
  });
});

describe('entity actions', () => {
  const vela = new Vela({
    policy: {
      id: 'actions',
      entities: { EMAIL: 'redact', ORG: 'allow', AADHAAR: 'fpe-synthetic', CREDIT_CARD: 'fpe-synthetic', GSTIN: 'fpe-synthetic', IBAN: 'fpe-synthetic', PAN: 'fpe-synthetic', SECRET_KEY: 'block' },
    },
  });

  it('redact is never restored; allow stays in clear text', () => {
    const s = vela.createSession();
    const masked = s.mask(`Mail ${SENTINELS.email} at Acme Technologies Pvt Ltd`);
    assert.ok(masked.includes('Acme Technologies Pvt Ltd'));
    assert.ok(masked.includes('[EMAIL_1]'));
    assert.equal(s.unmask(masked).text, masked.replace('Acme Technologies Pvt Ltd', 'Acme Technologies Pvt Ltd'));
    assert.ok(!s.unmask(masked).text.includes(SENTINELS.email));
  });

  it('fpe-synthetic output fails its checksum and still restores', () => {
    const s = vela.createSession();
    const text = `Aadhaar ${SENTINELS.aadhaar}, card ${SENTINELS.card}, GSTIN 27ABCDE1234F1Z5, IBAN GB82 WEST 1234 5698 7654 32, PAN ${SENTINELS.pan}`;
    const masked = s.mask(text);
    const reps = s.replacements;
    const of = (t: string) => reps.find((r) => r.type === t)?.masked ?? '';
    assert.equal(validateVerhoeff(of('AADHAAR')), false);
    assert.equal(validateLuhn(of('CREDIT_CARD')), false);
    assert.equal(validateGstin(of('GSTIN')), false);
    assert.equal(validateIban(of('IBAN')), false);
    assert.match(of('PAN'), /^\[PAN_\d+\]$/, 'types without a check character fall back to a placeholder');
    assert.equal(s.unmask(masked).text, text);
  });

  it('block rejects the request before anything is sent', async () => {
    const events: AuditEvent[] = [];
    const v = new Vela({ policy: { id: 'no-secrets', entities: { SECRET_KEY: 'block' } }, audit: (e) => { events.push(e); } });
    const up = await startUpstream();
    const proxy = runProxy(v, { port: 0, upstream: up.url });
    try {
      const res = await fetch(`${await baseUrlOf(proxy)}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: `${SENTINEL_TEXT} key sk-proj-abcdefghijklmnopqrstuvwxyz` }] }),
      });
      assert.equal(res.status, 422);
      const body = (await res.json()) as { error: { message: string } };
      assert.match(body.error.message, /blocks SECRET_KEY/);
      assertNoSentinel(body.error.message, 'error message');
      assert.equal(up.seen.length, 0);
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(events[0]?.event, 'vela.blocked');
      assert.equal(events[0]?.error_type, 'VelaPolicyBlockedError');
      assert.equal(events[0]?.policy_id, 'no-secrets');
      assert.match(events[0]?.policy_hash ?? '', /^sha256:/);
    } finally {
      await new Promise((r) => proxy.close(r));
      await up.close();
    }
  });
});

describe('request rules', () => {
  const policy = { id: 'rules', providers: { allow: ['127.0.0.1:*'] }, models: { allow: ['gpt-4.1*'] }, nonText: 'block' as const };

  it('enforces provider, model and non-text rules', async () => {
    const up = await startUpstream();
    const ok = runProxy(new Vela({ policy }), { port: 0, upstream: up.url });
    const wrongHost = runProxy(new Vela({ policy: { ...policy, providers: { allow: ['*.openai.azure.com'] } } }), { port: 0, upstream: up.url });
    const post = async (server: typeof ok, body: unknown) =>
      fetch(`${await baseUrlOf(server)}/v1/chat/completions`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    try {
      const text = { model: 'gpt-4.1-mini', messages: [{ role: 'user', content: 'hi' }] };
      assert.equal((await post(ok, text)).status, 200);
      assert.equal((await post(wrongHost, text)).status, 403);
      assert.equal((await post(ok, { ...text, model: 'other-model' })).status, 403);
      const image = { model: 'gpt-4.1', messages: [{ role: 'user', content: [{ type: 'text', text: 'see' }, { type: 'image_url', image_url: { url: 'data:image/png;base64,AAAA' } }] }] };
      const r = await post(ok, image);
      assert.equal(r.status, 422);
      assert.match(((await r.json()) as { error: { message: string } }).error.message, /image_url/);
      assert.equal(up.seen.length, 1);
    } finally {
      await Promise.all([ok, wrongHost].map((s) => new Promise((r) => s.close(r))));
      await up.close();
    }
  });

  it('client wrappers apply the same rules', async () => {
    const { wrapOpenAiClient } = await import('../src/index.js');
    const client = wrapOpenAiClient({ baseURL: 'https://api.openai.com/v1', chat: { completions: { create: async () => ({}) } } } as never, new Vela({ policy: { id: 'm', models: { allow: ['gpt-4.1*'] } } })) as never as { chat: { completions: { create: (p: unknown) => Promise<unknown> } } };
    await assert.rejects(client.chat.completions.create({ model: 'other', messages: [] }), VelaPolicyBlockedError);
    await client.chat.completions.create({ model: 'gpt-4.1', messages: [] });
  });
});

describe('policy schema stays in sync with the code', () => {
  it('actions, packs and top-level keys match', async () => {
    const { ENTITY_ACTIONS, DETECTOR_PACKS } = await import('../src/index.js');
    const { readFileSync } = await import('node:fs');
    const schema = JSON.parse(readFileSync('schemas/vela-policy.schema.json', 'utf8'));
    assert.deepEqual([...schema.$defs.action.enum].sort(), [...ENTITY_ACTIONS].sort());
    assert.deepEqual([...schema.properties.packs.items.enum].sort(), Object.keys(DETECTOR_PACKS).sort());
    assert.deepEqual(Object.keys(schema.properties).sort(), ['description', 'entities', 'id', 'models', 'ner', 'nonText', 'packs', 'providers', 'restore', 'version']);
    assert.equal(loadPolicy('examples/policies/bank.yaml').id, 'acme-bank-assistant');
  });
});
