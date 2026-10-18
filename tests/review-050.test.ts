/**
 * Regression tests for the review of the 0.5.0 compliance work. Each case
 * leaked, mis-restored or misreported before its fix.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  Vela,
  runProxy,
  wrapOpenAiClient,
  wrapAnthropicClient,
  maskOpenAiRequest,
  unmaskOpenAiResponse,
  maskLlmRequest,
  createSseTransformer,
  VelaRouteBlockedError,
  VelaPolicyBlockedError,
  type AuditEvent,
} from '../src/index.js';
import { SENTINELS, SENTINEL_TEXT, assertNoSentinel, startUpstream, baseUrlOf } from './helpers/leak-oracle.js';

type Any = any;  

describe('review findings on 0.5.0', () => {
  it('1. raw HTTP helpers on the client root and internals are blocked', () => {
    const rec = async () => ({});
    const client = wrapOpenAiClient({ chat: { completions: { create: rec } }, get: rec, delete: rec, post: rec, _client: { get: rec }, models: { list: rec } } as never, new Vela()) as Any;
    for (const call of [() => client.get('/chat/completions'), () => client.delete('/x', { body: SENTINEL_TEXT }), () => client._client.get('/x')]) {
      assert.throws(call, VelaRouteBlockedError);
    }
    client.models.list();
  });

  it('2. redacted values are never restored, through any path', () => {
    const vela = new Vela({ policy: { id: 'r', entities: { EMAIL: 'redact' } } });
    const r = vela.mask(`mail ${SENTINELS.email}`);
    assertNoSentinel(vela.unmask(r.text, r).text, 'legacy unmask');
    const { payload, results } = maskOpenAiRequest(vela, { messages: [{ role: 'user', content: `mail ${SENTINELS.email}` }] });
    const resp = unmaskOpenAiResponse(vela as never, { choices: [{ message: { role: 'assistant', content: payload.messages[0]?.content } }] } as never, results as never);
    assertNoSentinel(JSON.stringify(resp), 'unmaskOpenAiResponse');
  });

  it('3. parsed_arguments and Responses tool deltas keep placeholders', () => {
    const vela = new Vela({ restore: { toolArguments: 'placeholders' } });
    const s = vela.createSession();
    const m = s.mask(`mail ${SENTINELS.email}`).slice(5);
    const out = s.unmaskValue({ function: { arguments: JSON.stringify({ to: m }), parsed_arguments: { to: m } } });
    assertNoSentinel(JSON.stringify(out), 'parsed_arguments');
    const sse = createSseTransformer('openai-responses', s);
    let text = '';
    for (const type of ['response.custom_tool_call_input.delta', 'response.code_interpreter_call_code.delta']) {
      text += sse.push(`event: ${type}\ndata: ${JSON.stringify({ type, item_id: 'i', output_index: 0, delta: m })}\n\n`);
    }
    text += sse.end();
    assertNoSentinel(text, 'Responses tool deltas');
  });

  it('4. the residual pass looks at values, not just key names, and masks free-form keys', () => {
    const s = new Vela().createSession();
    const out = maskLlmRequest(s, 'openai-chat', {
      model: 'gpt-4.1',
      messages: [{ role: 'user', content: 'hi' }],
      metadata: { id: `card ${SENTINELS.card}`, data: SENTINELS.email, [SENTINELS.email]: 'x' },
    });
    assertNoSentinel(JSON.stringify(out), 'residual pass');
    assert.equal((out as Any).model, 'gpt-4.1');
    const blocked = new Vela({ policy: { id: 'b', entities: { CREDIT_CARD: 'block' } } }).createSession();
    assert.throws(() => maskLlmRequest(blocked, 'openai-chat', { messages: [], metadata: { id: `card ${SENTINELS.card}` } }), VelaPolicyBlockedError);
    const blob = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB';
    const img = maskLlmRequest(new Vela().createSession(), 'anthropic-messages', { messages: [{ role: 'user', content: [{ type: 'image', source: { type: 'base64', media_type: 'image/png', data: blob } }] }] });
    assert.equal((img as Any).messages[0].content[0].source.data, blob);
  });

  it('5. signed thinking blocks and MCP credentials reach the provider unchanged', () => {
    const vela = new Vela({ policy: { id: 'p', entities: { SECRET_KEY: 'block' }, restore: { thinking: 'placeholders' } } });
    const thinking = { type: 'thinking', thinking: 'The user is [EMAIL_1]; check the account.', signature: 'c2lnbmF0dXJlLWJ5LXByb3ZpZGVy' };
    const body = {
      model: 'm',
      mcp_servers: [{ type: 'url', url: 'https://mcp.example.com', name: 'crm', authorization_token: 'sk-proj-abcdefghijklmnopqrstuvwxyz123456' }],
      messages: [{ role: 'assistant', content: [thinking, { type: 'text', text: 'ok' }] }],
    };
    const out = maskLlmRequest(vela.createSession(), 'anthropic-messages', body) as Any;
    assert.deepEqual(out.messages[0].content[0], thinking);
    assert.equal(out.mcp_servers[0].authorization_token, body.mcp_servers[0]?.authorization_token);
    const tools = maskLlmRequest(vela.createSession(), 'openai-responses', { input: 'hi', tools: [{ type: 'mcp', server_url: 'https://mcp.example.com', headers: { Authorization: 'Bearer sk-proj-abcdefghijklmnopqrstuvwxyz123456' } }] }) as Any;
    assert.match(tools.tools[0].headers.Authorization, /^Bearer sk-proj-/);
  });

  it('7. SDK wrappers write audit events, and fail closed on a broken sink', async () => {
    const events: AuditEvent[] = [];
    const vela = new Vela({ audit: (e) => { events.push(e); } });
    const client = wrapAnthropicClient({ baseURL: 'https://api.anthropic.com', messages: { create: async (p: Any) => ({ content: [{ type: 'text', text: p.messages[0].content }] }) } } as never, vela) as Any;
    const r = await client.messages.create({ model: 'claude-x', max_tokens: 5, messages: [{ role: 'user', content: SENTINEL_TEXT }] });
    assert.equal(r.content[0].text, SENTINEL_TEXT);
    await new Promise((res) => setTimeout(res, 10));
    assert.deepEqual(events.map((e) => e.event), ['vela.request', 'vela.response']);
    assert.equal(events[0]?.route, '/v1/messages');
    assertNoSentinel(JSON.stringify(events), 'audit events');
    let called = false;
    const broken = wrapAnthropicClient({ messages: { create: async () => { called = true; return {}; } } } as never, new Vela({ audit: () => { throw new Error('down'); } })) as Any;
    await assert.rejects(broken.messages.create({ model: 'm', messages: [] }), /Audit log unavailable/);
    assert.equal(called, false);
  });

  it('8. a policy naming an unknown entity type is rejected', () => {
    assert.throws(() => new Vela({ policy: { id: 'x', entities: { CREDITCARD: 'block' } } }), /unknown entity type\(s\) CREDITCARD/);
    assert.throws(() => new Vela({ policy: { id: 'x', entities: { CARD_CVV: 'block' } } }), /unknown entity type/);
    new Vela({ policy: { id: 'x', packs: ['pci'], entities: { CARD_CVV: 'block' } } });
    new Vela({ policy: { id: 'x', entities: { EMP_ID: 'redact' } }, extraEntityTypes: ['EMP_ID'] });
  });

  it('9. failed logins are rate-limited per client', async () => {
    const up = await startUpstream();
    const proxy = runProxy(new Vela(), { port: 0, upstream: up.url, authTokens: { 'correct-token-0001': 't' } });
    try {
      const base = await baseUrlOf(proxy);
      const codes: number[] = [];
      for (let i = 0; i < 32; i++) codes.push((await fetch(`${base}/v1/models`, { headers: { 'x-vela-key': `guess-${i}` } })).status);
      assert.equal(codes[0], 401);
      assert.equal(codes.at(-1), 429);
    } finally {
      await new Promise((r) => proxy.close(r));
      await up.close();
    }
  });
});
