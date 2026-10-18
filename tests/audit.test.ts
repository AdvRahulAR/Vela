/**
 * Audit events (F3 in docs/COMPLIANCE_AUDIT.md): value-free, hash-chained,
 * written before forwarding (fail closed) and after the response.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Vela, runProxy, jsonlFileSink, verifyAuditChain, type AuditEvent } from '../src/index.js';
import { SENTINEL_TEXT, assertNoSentinel, startUpstream, baseUrlOf } from './helpers/leak-oracle.js';

const echo = (r: { body: string }, res: import('node:http').ServerResponse) => {
  const b = JSON.parse(r.body || '{}');
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ choices: [{ index: 0, message: { role: 'assistant', content: b.messages?.[0]?.content ?? '' } }] }));
};

const waitFor = async (cond: () => boolean) => {
  for (let i = 0; i < 100 && !cond(); i++) await new Promise((r) => setTimeout(r, 10));
};

describe('audit trail', () => {
  it('writes value-free, hash-chained request and response events', async () => {
    const file = join(mkdtempSync(join(tmpdir(), 'vela-audit-')), 'audit.jsonl');
    const vela = new Vela({ audit: jsonlFileSink(file), keyId: 'kms:test-key/1' });
    const up = await startUpstream(echo);
    const proxy = runProxy(vela, { port: 0, upstream: up.url });
    try {
      const base = await baseUrlOf(proxy);
      const res = await fetch(`${base}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'gpt-test', messages: [{ role: 'user', content: SENTINEL_TEXT }] }),
      });
      const body = (await res.json()) as { choices: Array<{ message: { content: string } }> };
      assert.equal(body.choices[0]?.message.content, SENTINEL_TEXT);
      const id = res.headers.get('x-vela-request-id');
      assert.ok(id);
      assert.equal((await fetch(`${base}/v1/messages/batches`, { method: 'POST', body: '{}' })).status, 403);
      await waitFor(() => readFileSync(file, 'utf8').trim().split('\n').length >= 3);

      const raw = readFileSync(file, 'utf8');
      assertNoSentinel(raw, 'audit log');
      const events = raw.trim().split('\n').map((l) => JSON.parse(l) as AuditEvent);
      assert.deepEqual(events.map((e) => e.event), ['vela.request', 'vela.response', 'vela.blocked']);
      const [reqEv, resEv, blocked] = events as [AuditEvent, AuditEvent, AuditEvent];
      assert.equal(reqEv.request_id, id);
      assert.equal(reqEv.model, 'gpt-test');
      assert.equal(reqEv.key_id, 'kms:test-key/1');
      assert.equal(reqEv.route, '/v1/chat/completions');
      assert.equal(reqEv.entities?.PAN, 1);
      assert.equal(reqEv.entities?.EMAIL, 1);
      assert.ok((reqEv.actions?.fpe ?? 0) >= 3);
      assert.equal(resEv.status, 200);
      assert.ok((resEv.restore?.restored.content ?? 0) >= 5);
      assert.equal(blocked.status, 403);
      assert.equal(blocked.error_type, 'VelaRouteBlockedError');
      const v = verifyAuditChain(raw);
      assert.ok(v.ok && v.events === 3);
      // Truncation is caught only against a head recorded elsewhere.
      const firstTwo = raw.split('\n').slice(0, 2).join('\n');
      assert.equal(verifyAuditChain(firstTwo).ok, true);
      assert.equal(verifyAuditChain(firstTwo, { expectHead: v.head }).ok, false);

      // Editing any line breaks the chain.
      writeFileSync(file, raw.replace('"status":200', '"status":201'));
      assert.deepEqual(verifyAuditChain(readFileSync(file, 'utf8')), { ok: false, line: 2 });
    } finally {
      await new Promise((r) => proxy.close(r));
      await up.close();
    }
  });

  it('continues an existing chain after a restart', async () => {
    const file = join(mkdtempSync(join(tmpdir(), 'vela-audit-')), 'audit.jsonl');
    const ev = { event: 'vela.blocked', request_id: 'r', ts: 't', vela_version: 'v', method: 'POST', route: '/x' } as AuditEvent;
    jsonlFileSink(file)(ev);
    jsonlFileSink(file)(ev);
    const v = verifyAuditChain(readFileSync(file, 'utf8'));
    assert.ok(v.ok && v.events === 2);
  });

  it('a failed write does not break the chain', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vela-audit-'));
    const file = join(dir, 'audit.jsonl');
    let failNext = false;
    const sink = jsonlFileSink(file, {
      append: (p, d) => {
        if (failNext) {
          failNext = false;
          throw new Error('disk full');
        }
        appendFileSync(p, d);
      },
    });
    const ev = { event: 'vela.blocked', request_id: 'r', ts: 't', vela_version: 'v', method: 'POST', route: '/x' } as AuditEvent;
    sink(ev);
    failNext = true;
    assert.throws(() => sink(ev), /disk full/);
    sink(ev);
    assert.ok(verifyAuditChain(readFileSync(file, 'utf8')).ok);
  });

  it('fails closed when the audit sink is unavailable', async () => {
    const vela = new Vela({ audit: () => { throw new Error('disk full'); } });
    const up = await startUpstream(echo);
    const proxy = runProxy(vela, { port: 0, upstream: up.url });
    try {
      const base = await baseUrlOf(proxy);
      const res = await fetch(`${base}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: SENTINEL_TEXT }] }),
      });
      assert.equal(res.status, 503);
      assert.equal(up.seen.length, 0);
    } finally {
      await new Promise((r) => proxy.close(r));
      await up.close();
    }
  });
});
