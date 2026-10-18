/**
 * Gemini (proxy, streaming) and AWS Bedrock (in-process SDK wrapper).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Vela, runProxy, wrapBedrockClient, VelaRouteBlockedError, type AuditEvent } from '../src/index.js';
import { SENTINEL_TEXT, SENTINELS, assertNoSentinel, startUpstream, baseUrlOf } from './helpers/leak-oracle.js';

type Any = any;  
const chunks = (s: string, n = 4): string[] => Array.from({ length: Math.ceil(s.length / n) }, (_, i) => s.slice(i * n, i * n + n));

describe('Gemini through the proxy', () => {
  it('masks requests and restores JSON and SSE responses, with tool args kept by policy', async () => {
    const up = await startUpstream((r, res) => {
      const body = JSON.parse(r.body);
      const masked = body.contents[0].parts[0].text as string;
      if (r.url.includes('alt=sse')) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        for (const c of chunks(masked)) res.write(`data: ${JSON.stringify({ candidates: [{ index: 0, content: { role: 'model', parts: [{ text: c }] } }] })}\r\n\r\n`);
        res.write(`data: ${JSON.stringify({ candidates: [{ index: 0, content: { role: 'model', parts: [{ functionCall: { name: 'send', args: { to: masked } } }] }, finishReason: 'STOP' }] })}\r\n\r\n`);
        res.end();
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ candidates: [{ content: { role: 'model', parts: [{ text: masked }, { functionCall: { name: 'send', args: { to: masked } } }] } }] }));
    });
    const proxy = runProxy(new Vela({ restore: { toolArguments: 'placeholders' } }), { port: 0, upstream: up.url });
    try {
      const base = await baseUrlOf(proxy);
      const req = { contents: [{ role: 'user', parts: [{ text: SENTINEL_TEXT }] }] };
      const post = (path: string) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req) });
      const json = (await (await post('/v1beta/models/gemini-2.5-flash:generateContent')).json()) as Any;
      assert.equal(json.candidates[0].content.parts[0].text, SENTINEL_TEXT);
      assertNoSentinel(JSON.stringify(json.candidates[0].content.parts[1]), 'function call args');
      const sse = await (await post('/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse')).text();
      const events = sse.split(/\r?\n\r?\n/).filter((b) => b.startsWith('data:')).map((b) => JSON.parse(b.slice(5)));
      const text = events.flatMap((e: Any) => e.candidates?.[0]?.content?.parts ?? []).map((p: Any) => p.text ?? '').join('');
      assert.equal(text, SENTINEL_TEXT);
      assertNoSentinel(JSON.stringify(events.flatMap((e: Any) => e.candidates?.[0]?.content?.parts ?? []).filter((p: Any) => p.functionCall)), 'streamed function call');
      assertNoSentinel(up.dump());
    } finally {
      await new Promise((r) => proxy.close(r));
      await up.close();
    }
  });
});

describe('Bedrock SDK wrapper', () => {
  class ConverseCommand { constructor(readonly input: Any) {} }
  class ConverseStreamCommand { constructor(readonly input: Any) {} }
  class InvokeModelCommand { constructor(readonly input: Any) {} }
  class InvokeModelWithResponseStreamCommand { constructor(readonly input: Any) {} }
  class ApplyGuardrailCommand { constructor(readonly input: Any) {} }
  class ListAsyncInvokesCommand { constructor(readonly input: Any) {} }
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const sent: Any[] = [];
  const fake = {
    config: { region: 'ap-south-1' },
    async send(cmd: Any) {
      sent.push(cmd.input);
      const name = cmd.constructor.name;
      if (name === 'ConverseCommand') {
        const t = cmd.input.messages[0].content[0].text;
        return { $metadata: { httpStatusCode: 200 }, output: { message: { role: 'assistant', content: [{ text: t }, { toolUse: { toolUseId: 'x', name: 'send', input: { to: t } } }] } } };
      }
      if (name === 'ConverseStreamCommand') {
        const t = cmd.input.messages[0].content[0].text as string;
        const events = [
          ...chunks(t).map((c) => ({ contentBlockDelta: { contentBlockIndex: 0, delta: { text: c } } })),
          { contentBlockStop: { contentBlockIndex: 0 } },
          ...chunks(JSON.stringify({ to: t })).map((c) => ({ contentBlockDelta: { contentBlockIndex: 1, delta: { toolUse: { input: c } } } })),
          { contentBlockStop: { contentBlockIndex: 1 } },
          { messageStop: { stopReason: 'end_turn' } },
        ];
        return { stream: (async function* () { yield* events; })() };
      }
      const body = JSON.parse(dec.decode(cmd.input.body));
      const t = body.messages[0].content as string;
      if (name === 'InvokeModelCommand') return { body: enc.encode(JSON.stringify({ content: [{ type: 'text', text: t }] })) };
      const evs = chunks(t).map((c) => ({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: c } }));
      return { body: (async function* () { for (const e of [...evs, { type: 'content_block_stop', index: 0 }, { type: 'message_stop' }]) yield { chunk: { bytes: enc.encode(JSON.stringify(e)) } }; })() };
    },
  };

  it('masks Converse and InvokeModel (sync and streaming) and audits them', async () => {
    const events: AuditEvent[] = [];
    const client = wrapBedrockClient(fake, new Vela({ restore: { toolArguments: 'placeholders' }, audit: (e) => { events.push(e); } })) as Any;
    const conv = await client.send(new ConverseCommand({ modelId: 'anthropic.claude-x', messages: [{ role: 'user', content: [{ text: SENTINEL_TEXT }] }] }));
    assert.equal(conv.output.message.content[0].text, SENTINEL_TEXT);
    assertNoSentinel(JSON.stringify(conv.output.message.content[1]), 'Converse toolUse');

    const stream = await client.send(new ConverseStreamCommand({ modelId: 'm', messages: [{ role: 'user', content: [{ text: SENTINEL_TEXT }] }] }));
    let text = '';
    let tool = '';
    for await (const ev of stream.stream) {
      text += ev.contentBlockDelta?.delta?.text ?? '';
      tool += ev.contentBlockDelta?.delta?.toolUse?.input ?? '';
    }
    assert.equal(text, SENTINEL_TEXT);
    assertNoSentinel(tool, 'ConverseStream tool input');

    const body = enc.encode(JSON.stringify({ anthropic_version: 'bedrock-2023-05-31', max_tokens: 10, messages: [{ role: 'user', content: SENTINEL_TEXT }] }));
    const inv = await client.send(new InvokeModelCommand({ modelId: 'anthropic.claude-x', body }));
    assert.equal(JSON.parse(dec.decode(inv.body)).content[0].text, SENTINEL_TEXT);
    const invS = await client.send(new InvokeModelWithResponseStreamCommand({ modelId: 'anthropic.claude-x', body }));
    let streamed = '';
    for await (const c of invS.body) streamed += JSON.parse(dec.decode(c.chunk.bytes)).delta?.text ?? '';
    assert.equal(streamed, SENTINEL_TEXT);

    assertNoSentinel(JSON.stringify(sent.map((i) => ({ ...i, body: i.body ? dec.decode(i.body instanceof Uint8Array ? i.body : enc.encode(i.body)) : undefined }))), 'Bedrock');
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(events.filter((e) => e.event === 'vela.response').length, 4);
    assert.equal(events[0]?.upstream, 'bedrock-runtime.ap-south-1.amazonaws.com');
  });

  it('blocks commands and model bodies it cannot mask', async () => {
    const client = wrapBedrockClient(fake, new Vela()) as Any;
    await assert.rejects(client.send(new ApplyGuardrailCommand({ content: [{ text: { text: SENTINELS.email } }] })), VelaRouteBlockedError);
    await assert.rejects(client.send(new InvokeModelCommand({ modelId: 'amazon.titan', body: JSON.stringify({ inputText: SENTINEL_TEXT }) })), /only Anthropic model bodies/);
    await client.send(new ListAsyncInvokesCommand({})).catch(() => undefined);
  });
});
