/**
 * Regression tests for the review of Gemini, Bedrock, metrics and deployment.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  Vela,
  runProxy,
  createFetchInterceptor,
  forwardLlmRequest,
  maskLlmRequest,
  enforceRequestPolicy,
  VelaRouteBlockedError,
  VelaPolicyBlockedError,
} from '../src/index.js';
import { SENTINELS, SENTINEL_TEXT, assertNoSentinel, baseUrlOf } from './helpers/leak-oracle.js';

type Any = any;  

describe('review findings: providers', () => {
  it('1. Vertex global endpoint gets provider route rules', async () => {
    const real = globalThis.fetch;
    let sent = '';
    globalThis.fetch = (async (_: unknown, init?: RequestInit) => {
      sent += String(init?.body ?? '');
      return new Response('{}', { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;
    try {
      const f = createFetchInterceptor(new Vela());
      const body = JSON.stringify({ anthropic_version: 'vertex-2023-10-16', messages: [{ role: 'user', content: SENTINEL_TEXT }] });
      await assert.rejects(f('https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/anthropic/models/claude:rawPredict', { method: 'POST', body }), VelaRouteBlockedError);
      assertNoSentinel(sent);
    } finally {
      globalThis.fetch = real;
    }
  });

  it('2. Gemini thought parts follow the thinking restore policy in JSON responses', () => {
    const s = new Vela({ restore: { thinking: 'placeholders' } }).createSession();
    const m = s.mask(`mail ${SENTINELS.email}`).slice(5);
    const out = s.unmaskValue({ candidates: [{ content: { parts: [{ text: m, thought: true }, { text: m }] } }] }) as Any;
    assertNoSentinel(out.candidates[0].content.parts[0].text, 'thought part');
    assert.equal(out.candidates[0].content.parts[1].text, SENTINELS.email);
  });

  it('3. an operator key is only sent to its own provider', async () => {
    const seen: Array<{ url: string; headers: Headers }> = [];
    const fetchImpl = (async (url: string, init: RequestInit) => {
      seen.push({ url, headers: new Headers(init.headers) });
      return new Response('{}', { headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    {
      const { selectApiKey } = await import('../src/integrations/gateway.js');
      const auto = { apiKey: 'sk-openai-operator', apiKeys: { anthropic: 'sk-ant-operator' } };
      assert.equal(selectApiKey(auto, 'https://generativelanguage.googleapis.com/v1beta/models/g:generateContent', 'gemini'), undefined);
      assert.equal(selectApiKey(auto, 'https://api.anthropic.com/v1/messages', 'anthropic-messages'), 'sk-ant-operator');
      assert.equal(selectApiKey(auto, 'https://api.openai.com/v1/chat/completions', 'openai-chat'), 'sk-openai-operator');
      assert.equal(selectApiKey({ upstream: 'https://gw.example', apiKey: 'k' }, 'https://gw.example/v1/messages', 'anthropic-messages'), 'k');
      await forwardLlmRequest(new Vela(), { url: 'https://generativelanguage.googleapis.com/v1beta/models/g:generateContent', method: 'POST', headers: new Headers(), body: JSON.stringify({ contents: [] }) }, { fetchImpl });
      assert.equal(seen[0]?.headers.get('x-goog-api-key'), null);
    }
  });

  it('4. Gemini model allowlist uses the model in the path', () => {
    const vela = new Vela({ policy: { id: 'm', models: { allow: ['gemini-2.5-flash'] } } });
    const url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent';
    assert.throws(() => enforceRequestPolicy(vela, url, { model: 'gemini-2.5-flash', contents: [] }), VelaPolicyBlockedError);
    enforceRequestPolicy(vela, url.replace('pro', 'flash'), { contents: [] });
  });

  it('5. Bedrock bytes survive; text documents are masked', () => {
    const png = new Uint8Array([137, 80, 78, 71, 1, 2, 3]);
    const doc = new TextEncoder().encode(`Statement for ${SENTINEL_TEXT}`);
    const out = maskLlmRequest(new Vela().createSession(), 'bedrock-converse', {
      messages: [{ role: 'user', content: [{ image: { format: 'png', source: { bytes: png } } }, { document: { format: 'txt', name: 'stmt', source: { bytes: doc } } }] }],
    }) as Any;
    assert.ok(out.messages[0].content[0].image.source.bytes instanceof Uint8Array);
    assert.deepEqual(out.messages[0].content[0].image.source.bytes, png);
    assertNoSentinel(new TextDecoder().decode(out.messages[0].content[1].document.source.bytes), 'Bedrock text document');
  });

  it('6. /readyz is cached and /metrics has no tenant labels by default', async () => {
    let calls = 0;
    const vela = new Vela({ asyncRecognizers: [async (t) => { calls++; return t.map(() => []); }] });
    const proxy = runProxy(vela, { port: 0, authTokens: { 'tok-for-tenant-acme': 'acme-secret-tenant' } });
    try {
      const base = await baseUrlOf(proxy);
      for (let i = 0; i < 5; i++) assert.equal((await fetch(`${base}/readyz`)).status, 200);
      assert.equal(calls, 1);
      await fetch(`${base}/v1/models`, { headers: { 'x-vela-key': 'tok-for-tenant-acme' } });
      assert.doesNotMatch(await (await fetch(`${base}/metrics`)).text(), /acme-secret-tenant/);
    } finally {
      await new Promise((r) => proxy.close(r));
    }
  });
});
