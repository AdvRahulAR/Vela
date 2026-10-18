/**
 * Proxy hardening (F8 in docs/COMPLIANCE_AUDIT.md): authentication, tenants,
 * rate limits, and refusing to listen beyond loopback without authentication.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Vela, runProxy, type AuditEvent } from '../src/index.js';
import { SENTINELS, startUpstream, baseUrlOf } from './helpers/leak-oracle.js';

const close = (s: { close: (cb: () => void) => void }) => new Promise<void>((r) => s.close(() => r()));

describe('proxy authentication', () => {
  it('refuses a non-loopback host without authentication', () => {
    assert.throws(() => runProxy(new Vela(), { port: 0, host: '0.0.0.0' }), /without authentication/);
  });

  it('allows it with insecure: true', async () => {
    const s = runProxy(new Vela(), { port: 0, host: '0.0.0.0', insecure: true });
    await new Promise((r) => s.once('listening', r));
    await close(s);
  });

  it('requires a valid token, records the tenant and does not forward the token', async () => {
    const events: AuditEvent[] = [];
    const up = await startUpstream();
    const proxy = runProxy(new Vela({ audit: (e) => { events.push(e); } }), { port: 0, upstream: up.url, authTokens: { 'tok-alpha-123': 'alpha' } });
    try {
      const base = await baseUrlOf(proxy);
      const body = JSON.stringify({ model: 'm', messages: [{ role: 'user', content: 'hi' }] });
      const send = (key?: string) =>
        fetch(`${base}/v1/chat/completions`, { method: 'POST', headers: { 'content-type': 'application/json', ...(key ? { 'x-vela-key': key } : {}) }, body });
      assert.equal((await send()).status, 401);
      assert.equal((await send('tok-alpha-12')).status, 401);
      assert.equal(up.seen.length, 0);
      assert.equal((await send('tok-alpha-123')).status, 200);
      assert.equal(up.seen[0]?.headers['x-vela-key'], undefined);
      assert.equal((await fetch(`${base}/health`)).status, 200, 'health stays open');
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(events.find((e) => e.event === 'vela.request')?.tenant, 'alpha');
    } finally {
      await close(proxy);
      await up.close();
    }
  });

  it('binds caller-chosen session ids to the tenant', async () => {
    const up = await startUpstream();
    const vela = new Vela({ fpeKey: new Uint8Array(32).fill(3) });
    const proxy = runProxy(vela, { port: 0, upstream: up.url, authTokens: { ta: 'alpha', tb: 'beta' } });
    try {
      const base = await baseUrlOf(proxy);
      for (const key of ['ta', 'tb']) {
        await fetch(`${base}/v1/chat/completions`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-vela-key': key, 'x-vela-session': 'conv-1' },
          body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: `PAN ${SENTINELS.pan}` }] }),
        });
      }
      const pans = up.seen.map((s) => /PAN ([A-Z]{5}\d{4}[A-Z])/.exec(s.body)?.[1]);
      assert.ok(pans[0] && pans[1]);
      assert.notEqual(pans[0], pans[1], 'two tenants with the same session id get different ciphertexts');
    } finally {
      await close(proxy);
      await up.close();
    }
  });

  it('rate-limits per client', async () => {
    const up = await startUpstream();
    const proxy = runProxy(new Vela(), { port: 0, upstream: up.url, rateLimitPerMinute: 2 });
    try {
      const base = await baseUrlOf(proxy);
      const codes = [];
      for (let i = 0; i < 3; i++) codes.push((await fetch(`${base}/v1/models`)).status);
      assert.deepEqual(codes, [200, 200, 429]);
    } finally {
      await close(proxy);
      await up.close();
    }
  });
});
