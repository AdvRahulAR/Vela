/**
 * Operations endpoints: Prometheus metrics (counts only) and readiness.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Vela, runProxy } from '../src/index.js';
import { SENTINEL_TEXT, assertNoSentinel, startUpstream, baseUrlOf } from './helpers/leak-oracle.js';

const close = (s: { close: (cb: () => void) => void }) => new Promise<void>((r) => s.close(() => r()));

describe('ops endpoints', () => {
  it('/metrics counts requests, entities and blocks without values', async () => {
    const up = await startUpstream();
    const proxy = runProxy(new Vela(), { port: 0, upstream: up.url, authTokens: { 'metrics-token-0001': 'ops' } });
    try {
      const base = await baseUrlOf(proxy);
      const h = { 'content-type': 'application/json', 'x-vela-key': 'metrics-token-0001' };
      await fetch(`${base}/v1/chat/completions`, { method: 'POST', headers: h, body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: SENTINEL_TEXT }] }) });
      await fetch(`${base}/v1/batches`, { method: 'POST', headers: h, body: '{}' });
      await new Promise((r) => setTimeout(r, 20));
      const res = await fetch(`${base}/metrics`);
      assert.equal(res.status, 200, 'metrics need no client token');
      const text = await res.text();
      assertNoSentinel(text, 'metrics');
      assert.match(text, /vela_requests_total\{format="openai-chat",outcome="forwarded",tenant="ops"\} 1/);
      assert.match(text, /vela_entities_detected_total\{type="PAN",tenant="ops"\} 1/);
      assert.match(text, /vela_blocked_total\{reason="VelaRouteBlockedError"\} 1/);
      assert.match(text, /vela_request_duration_seconds_count 1/);
    } finally {
      await close(proxy);
      await up.close();
    }
  });

  it('/readyz reports NER health', async () => {
    const ok = new Vela({ asyncRecognizers: [async (texts) => texts.map(() => [])] });
    const down = new Vela({ asyncRecognizers: [async () => { throw new Error('down'); }] });
    assert.deepEqual(await new Vela().checkReady(), { ready: true, ner: 'none' });
    assert.deepEqual(await ok.checkReady(), { ready: true, ner: 'ok' });
    const proxy = runProxy(down, { port: 0 });
    try {
      const res = await fetch(`${await baseUrlOf(proxy)}/readyz`);
      assert.equal(res.status, 503);
      assert.deepEqual(await res.json(), { status: 'not_ready', ner: 'failed' });
    } finally {
      await close(proxy);
    }
  });
});
