import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Vela } from '../src/core/vela.js';
import { QuantumKeyManager } from '../src/core/quantum.js';
import { maskOpenAiRequest, unmaskOpenAiResponse, wrapOpenAiClient } from '../src/integrations/openai.js';
import type { OpenAIRequest, OpenAIResponse } from '../src/types.js';

describe('OpenAI SDK Integration', () => {
  const kp = QuantumKeyManager.generateKeyPair();
  const { sharedSecret } = QuantumKeyManager.encapsulate(kp.publicKey);
  const fpeKey = QuantumKeyManager.deriveFpeKey(sharedSecret);
  const vela = new Vela({ fpeKey });

  it('should mask text messages and tool call arguments', () => {
    const request: OpenAIRequest = {
      messages: [
        {
          role: 'user',
          content: 'My PAN is ABCDE1234F and email is test@domain.com.',
        },
        {
          role: 'assistant',
          tool_calls: [
            {
              id: 'call_1',
              type: 'function',
              function: {
                name: 'verify_user',
                arguments: '{"pan":"ABCDE1234F"}',
              },
            },
          ],
        },
      ],
    };

    const { payload, results } = maskOpenAiRequest(vela, request);

    // Prompt content masked
    const userMsg = payload.messages[0];
    assert.ok(typeof userMsg?.content === 'string');
    assert.doesNotMatch(userMsg.content, /ABCDE1234F/);
    assert.doesNotMatch(userMsg.content, /test@domain\.com/);

    // Tool call arguments masked
    const toolMsg = payload.messages[1];
    const args = toolMsg?.tool_calls?.[0]?.function?.arguments;
    assert.ok(typeof args === 'string');
    assert.doesNotMatch(args, /ABCDE1234F/);

    // Response unmasking
    const mockResponse: OpenAIResponse = {
      choices: [
        {
          message: {
            role: 'assistant',
            content: `Confirmed identity for ${userMsg.content}`,
          },
        },
      ],
    };

    const unmasked = unmaskOpenAiResponse(vela, mockResponse, results);
    const content = unmasked.choices?.[0]?.message?.content;
    assert.ok(typeof content === 'string');
    assert.match(content, /ABCDE1234F/);
    assert.match(content, /test@domain\.com/);
  });

  it('should wrap client chat.completions.create seamlessly', async () => {
    const mockClient = {
      chat: {
        completions: {
          create: async (params: OpenAIRequest) => {
            const userContent = params.messages[0]?.content;
            return {
              choices: [
                {
                  message: {
                    role: 'assistant',
                    content: `Echo: ${userContent}`,
                  },
                },
              ],
            };
          },
        },
      },
    };

    const originalFunction = mockClient.chat.completions.create;
    const wrapped = wrapOpenAiClient(mockClient, vela);
    const response = (await wrapped.chat.completions.create({
      messages: [{ role: 'user', content: 'Contact me at admin@privacy.com' }],
    })) as OpenAIResponse;

    const content = response.choices?.[0]?.message?.content;
    assert.ok(typeof content === 'string');
    assert.match(content, /admin@privacy\.com/);

    // Verify original client was NOT mutated
    assert.equal(mockClient.chat.completions.create, originalFunction);
  });

  it('should intercept requests with createExpressMiddleware', async () => {
    const { createExpressMiddleware } = await import('../src/integrations/express.js');
    const middleware = createExpressMiddleware(vela);

    const makeReq = () => ({
      path: '/v1/chat/completions',
      body: {
        messages: [{ role: 'user', content: 'Secret project Neeti with PAN ABCDE1234F' }],
      },
      headers: {},
    });
    const makeRes = () => {
      const out = { status: 0, json: undefined as unknown, written: '' };
      const res = {
        status: (code: number) => {
          out.status = code;
          return res;
        },
        json: (body: unknown) => {
          out.json = body;
        },
        setHeader: () => {},
        write: (chunk: unknown) => {
          out.written += Buffer.from(chunk as Uint8Array).toString('utf8');
          return true;
        },
        end: () => {},
      };
      return { res, out };
    };

    const realFetch = globalThis.fetch;
    try {
      // Upstream echoes the (masked) user content back, so the client must see it restored.
      let upstreamBody = '';
      globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
        upstreamBody = String(init?.body ?? '');
        const sent = JSON.parse(upstreamBody) as { messages: { content: string }[] };
        return new Response(
          JSON.stringify({ choices: [{ message: { role: 'assistant', content: `Echo: ${sent.messages[0]?.content}` } }] }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }) as typeof fetch;

      let nextCalled = false;
      const ok = makeRes();
      await middleware(makeReq(), ok.res, () => {
        nextCalled = true;
      });
      assert.equal(nextCalled, false);
      assert.equal(ok.out.status, 200);
      assert.doesNotMatch(upstreamBody, /ABCDE1234F/);
      assert.match(ok.out.written, /ABCDE1234F/);

      // Upstream failure yields a structured 502 instead of calling next()
      globalThis.fetch = (async () => {
        throw new Error('network down');
      }) as typeof fetch;
      const failed = makeRes();
      await middleware(makeReq(), failed.res, () => {
        nextCalled = true;
      });
      assert.equal(nextCalled, false);
      assert.equal(failed.out.status, 502);
      assert.ok(failed.out.json);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
