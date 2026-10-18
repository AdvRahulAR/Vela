/**
 * Route matrix: every body-carrying route of the providers Vela fronts must be
 * either masked or blocked. When a provider adds a route, add it here.
 * Guards against F1 (unrecognised routes forwarded unmasked) in
 * docs/COMPLIANCE_AUDIT.md.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Vela, runProxy, createFetchInterceptor, classifyRoute, VelaRouteBlockedError } from '../src/index.js';
import { SENTINEL_TEXT, assertNoSentinel, findSentinels, startUpstream, baseUrlOf, type MockUpstream } from './helpers/leak-oracle.js';

const chat = { model: 'm', messages: [{ role: 'user', content: SENTINEL_TEXT }] };
const anthropic = { model: 'm', max_tokens: 10, system: SENTINEL_TEXT, messages: [{ role: 'user', content: SENTINEL_TEXT }] };

/** Routes whose text must reach the upstream masked. */
const MASKED: Array<[string, unknown]> = [
  ['/v1/chat/completions', chat],
  ['/v1/responses', { model: 'm', input: SENTINEL_TEXT, instructions: SENTINEL_TEXT }],
  ['/v1/responses/input_tokens', { model: 'm', input: SENTINEL_TEXT }],
  ['/v1/messages', anthropic],
  ['/v1/messages/count_tokens', anthropic],
  ['/v1/completions', { model: 'm', prompt: [SENTINEL_TEXT, SENTINEL_TEXT] }],
  ['/v1/embeddings', { model: 'm', input: SENTINEL_TEXT }],
  ['/v1/moderations', { model: 'm', input: [SENTINEL_TEXT] }],
];

/** Routes Vela cannot mask and restore (asynchronous results, files, audio…): rejected. */
const BLOCKED: Array<[string, unknown]> = [
  ['/v1/messages/batches', { requests: [{ custom_id: 'a', params: anthropic }] }],
  ['/v1/batches', { input_file_id: 'f', endpoint: '/v1/chat/completions' }],
  ['/v1/files', { purpose: 'batch', file: SENTINEL_TEXT }],
  ['/v1/uploads', { filename: SENTINEL_TEXT }],
  ['/v1/audio/speech', { model: 'm', input: SENTINEL_TEXT }],
  ['/v1/images/generations', { prompt: SENTINEL_TEXT }],
  ['/v1/threads/t1/messages', { role: 'user', content: SENTINEL_TEXT }],
  ['/v1/threads/runs', { assistant_id: 'a', thread: { messages: [{ role: 'user', content: SENTINEL_TEXT }] } }],
  ['/v1/assistants', { model: 'm', instructions: SENTINEL_TEXT }],
  ['/v1/conversations', { items: [{ type: 'message', role: 'user', content: SENTINEL_TEXT }] }],
  ['/v1/fine_tuning/jobs', { training_file: 'f', suffix: SENTINEL_TEXT }],
  ['/v1/some/future/endpoint', { anything: SENTINEL_TEXT }],
];

describe('classifyRoute', () => {
  it('classifies every masked route as maskable', () => {
    for (const [path] of MASKED) assert.notEqual(classifyRoute('POST', path).kind, 'blocked', path);
  });
  it('blocks every unmaskable body-carrying route', () => {
    for (const [path] of BLOCKED) assert.equal(classifyRoute('POST', path).kind, 'blocked', path);
  });
  it('treats body-free methods as safe', () => {
    for (const m of ['GET', 'HEAD', 'OPTIONS', 'DELETE']) assert.equal(classifyRoute(m, '/v1/models').kind, 'safe');
  });
  it('blocks PUT and PATCH on unknown routes', () => {
    assert.equal(classifyRoute('PATCH', '/v1/whatever').kind, 'blocked');
    assert.equal(classifyRoute('PUT', '/v1/whatever').kind, 'blocked');
  });
});

describe('proxy route matrix (leak oracle)', () => {
  const vela = new Vela();
  let up: MockUpstream;
  let base: string;
  let open: string;
  let servers: Array<ReturnType<typeof runProxy>> = [];

  before(async () => {
    up = await startUpstream();
    const strict = runProxy(vela, { port: 0, upstream: up.url });
    const all = runProxy(vela, { port: 0, upstream: up.url, passthrough: 'all' });
    servers = [strict, all];
    base = await baseUrlOf(strict);
    open = await baseUrlOf(all);
  });
  after(async () => {
    await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
    await up.close();
  });

  const post = (b: string, path: string, body: unknown) =>
    fetch(b + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

  for (const [path, body] of MASKED) {
    it(`masks ${path}`, async () => {
      const before = up.seen.length;
      const res = await post(base, path, body);
      assert.equal(res.status, 200, path);
      const got = up.seen.slice(before);
      assert.equal(got.length, 1, `${path} reached the upstream once`);
      assertNoSentinel(got.map((s) => s.body).join('\n'));
    });
  }

  for (const [path, body] of BLOCKED) {
    it(`blocks ${path} with 403 and sends nothing`, async () => {
      const before = up.seen.length;
      const res = await post(base, path, body);
      assert.equal(res.status, 403, path);
      const err = (await res.json()) as { error: { type: string } };
      assert.equal(err.error.type, 'vela_route_blocked');
      assert.equal(up.seen.length, before, `${path} must not reach the upstream`);
    });
  }

  it('forwards body-free routes', async () => {
    assert.equal((await fetch(`${base}/v1/models`)).status, 200);
  });

  it('passthrough "all" forwards unknown routes only when explicitly chosen', async () => {
    const before = up.seen.length;
    const res = await post(open, '/v1/some/future/endpoint', { anything: 'x' });
    assert.equal(res.status, 200);
    assert.equal(up.seen.length, before + 1);
  });
});

describe('fetch interceptor route matrix (leak oracle)', () => {
  it('masks or blocks every route on a provider host, whatever the body type', async () => {
    const up = await startUpstream();
    const real = globalThis.fetch;
    // Route the provider hostname to the mock upstream so the provider-host rules apply.
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      const u = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
      return real(up.url + u.pathname + u.search, init);
    }) as typeof fetch;
    try {
      const f = createFetchInterceptor(new Vela());
      const bodies = (o: unknown): BodyInit[] => {
        const s = JSON.stringify(o);
        return [s, new TextEncoder().encode(s), new Blob([s]), new TextEncoder().encode(s).buffer as ArrayBuffer,
          new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(s)); c.close(); } })];
      };
      for (const [path, body] of MASKED) {
        for (const b of bodies(body)) {
          const init: RequestInit & { duplex?: string } = { method: 'POST', body: b, duplex: 'half' };
          const res = await f(`https://api.anthropic.com${path}`, init);
          assert.equal(res.status, 200, path);
        }
      }
      assertNoSentinel(up.dump());
      for (const [path, body] of BLOCKED) {
        await assert.rejects(f(`https://api.openai.com${path}`, { method: 'POST', body: JSON.stringify(body) }), VelaRouteBlockedError, path);
      }
      assert.deepEqual(findSentinels(up.dump()), []);
      // Unparseable JSON on an LLM route is rejected, not sent as-is.
      await assert.rejects(f('https://api.openai.com/v1/chat/completions', { method: 'POST', body: `not json ${SENTINEL_TEXT}` }));
      assertNoSentinel(up.dump());
    } finally {
      globalThis.fetch = real;
      await up.close();
    }
  });
});

describe('client wrapper method matrix (leak oracle)', async () => {
  const { wrapOpenAiClient, wrapAnthropicClient } = await import('../src/index.js');
  const vela = new Vela();
  const sent: unknown[] = [];
  const rec = async (p: unknown) => {
    sent.push(p);
    return { ok: true };
  };
  const tree = (paths: string[]) => {
    const root: Record<string, any> = {};  
    for (const p of paths) {
      const parts = p.split('.');
      let node = root;
      for (const k of parts.slice(0, -1)) node = node[k] ??= {};
      node[parts.at(-1) as string] = rec;
    }
    return root;
  };

  it('OpenAI: masks text methods and blocks the rest', async () => {
    const masked = ['chat.completions.create', 'chat.completions.parse', 'responses.create', 'responses.parse', 'responses.inputTokens.count', 'completions.create', 'embeddings.create', 'moderations.create'];
    const blocked = ['chat.completions.stream', 'responses.stream', 'batches.create', 'files.create', 'audio.speech.create', 'beta.threads.messages.create', 'images.generate'];
    const client = wrapOpenAiClient(tree([...masked, ...blocked, 'models.list']) as never, vela) as Record<string, any>;  
    const params = (p: string) =>
      p.startsWith('chat.') ? chat
        : p.startsWith('responses.') ? { model: 'm', input: SENTINEL_TEXT, instructions: SENTINEL_TEXT }
          : p.startsWith('completions.') ? { model: 'm', prompt: SENTINEL_TEXT }
            : { model: 'm', input: SENTINEL_TEXT };
    const at = (p: string): any => p.split('.').reduce((o: any, k) => o[k], client);  
    for (const p of masked) await at(p)(structuredClone(params(p)));
    assert.equal(sent.length, masked.length);
    assertNoSentinel(JSON.stringify(sent), 'OpenAI SDK');
    for (const p of blocked) assert.throws(() => at(p)(structuredClone(params(p))), VelaRouteBlockedError, p);
    await client.models.list();
    assert.equal(sent.length, masked.length + 1);
  });

  it('Anthropic: masks messages and count_tokens, blocks stream() and batches', async () => {
    sent.length = 0;
    const masked = ['messages.create', 'messages.countTokens', 'beta.messages.create', 'beta.messages.countTokens'];
    const blocked = ['messages.stream', 'messages.batches.create', 'beta.messages.batches.create'];
    const client = wrapAnthropicClient(tree([...masked, ...blocked]) as never, vela) as Record<string, any>;  
    const at = (p: string): any => p.split('.').reduce((o: any, k) => o[k], client);  
    for (const p of masked) await at(p)(structuredClone(anthropic));
    assertNoSentinel(JSON.stringify(sent), 'Anthropic SDK');
    for (const p of blocked) assert.throws(() => at(p)(structuredClone(anthropic)), VelaRouteBlockedError, p);
  });
});
