/**
 * Regression tests for the CodeRabbit review of PR #7.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { Vela, runProxy, maskLlmRequest, wrapBedrockClient, createExpressMiddleware, type AuditEvent } from '../src/index.js';
import { SENTINELS, SENTINEL_TEXT, assertNoSentinel, startUpstream, baseUrlOf } from './helpers/leak-oracle.js';

type Any = any;  

describe('CodeRabbit findings on PR #7', () => {
  it('a signed thinking block with personal data is masked, not exempted', () => {
    const vela = new Vela({ restore: { thinking: 'placeholders' } });
    const clean = { type: 'thinking', thinking: 'Check the account balance first.', signature: 'c2lnbmF0dXJlLWJ5LXByb3ZpZGVy' };
    const dirty = { type: 'thinking', thinking: `The user is ${SENTINELS.email}.`, signature: 'c2lnbmF0dXJlLWJ5LXByb3ZpZGVy' };
    const out = maskLlmRequest(vela.createSession(), 'anthropic-messages', { messages: [{ role: 'assistant', content: [clean, dirty] }] }) as Any;
    assert.deepEqual(out.messages[0].content[0], clean);
    assertNoSentinel(JSON.stringify(out.messages[0].content[1]), 'thinking block');
  });

  it('Bedrock InvokeModel response keeps transformToString()', async () => {
    class InvokeModelCommand { constructor(readonly input: Any) {} }
    const enc = new TextEncoder();
    const client = wrapBedrockClient({
      async send(cmd: Any) {
        const t = JSON.parse(new TextDecoder().decode(cmd.input.body)).messages[0].content;
        const bytes = enc.encode(JSON.stringify({ content: [{ type: 'text', text: t }] }));
        return { body: Object.assign(bytes, { transformToString: () => new TextDecoder().decode(bytes) }) };
      },
    }, new Vela()) as Any;
    const r = await client.send(new InvokeModelCommand({ modelId: 'anthropic.c', body: enc.encode(JSON.stringify({ anthropic_version: 'bedrock-2023-05-31', messages: [{ role: 'user', content: SENTINEL_TEXT }] })) }));
    assert.equal(JSON.parse(r.body.transformToString()).content[0].text, SENTINEL_TEXT);
  });

  it('Express routes Gemini paths to the Gemini API', async () => {
    const urls: string[] = [];
    const real = globalThis.fetch;
    globalThis.fetch = (async (url: string) => {
      urls.push(String(url));
      return new Response('{}', { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;
    try {
      const mw = createExpressMiddleware(new Vela());
      const res: Any = { status() { return res; }, json() {}, setHeader() {}, write() { return true; }, end() {} };
      await mw({ path: '/v1beta/models/g:generateContent', method: 'POST', headers: {}, body: { contents: [] } }, res, () => {});
      assert.match(urls[0] ?? '', /^https:\/\/generativelanguage\.googleapis\.com\//);
    } finally {
      globalThis.fetch = real;
    }
  });

  it("passthrough 'all' audits unmasked forwards and fails closed without the sink", async () => {
    const events: AuditEvent[] = [];
    const up = await startUpstream();
    const ok = runProxy(new Vela({ audit: (e) => { events.push(e); } }), { port: 0, upstream: up.url, passthrough: 'all' });
    const broken = runProxy(new Vela({ audit: () => { throw new Error('down'); } }), { port: 0, upstream: up.url, passthrough: 'all' });
    try {
      const post = async (s: typeof ok) => fetch(`${await baseUrlOf(s)}/v1/batches`, { method: 'POST', body: '{}' });
      assert.equal((await post(ok)).status, 200);
      assert.equal(events[0]?.format, 'unmasked-passthrough');
      const before = up.seen.length;
      assert.equal((await post(broken)).status, 503);
      assert.equal(up.seen.length, before);
    } finally {
      await Promise.all([ok, broken].map((s) => new Promise((r) => s.close(r))));
      await up.close();
    }
  });

  it('eval --report requires --generated', () => {
    const r = spawnSync(process.execPath, ['--import', 'tsx', 'scripts/eval-corpus.ts', '--report'], { encoding: 'utf8' });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /use it with --generated/);
  });
});
