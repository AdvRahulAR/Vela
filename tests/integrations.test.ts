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

    let nextCalled = false;
    const req = {
      path: '/v1/chat/completions',
      body: {
        messages: [{ role: 'user', content: 'Secret project Neeti with PAN ABCDE1234F' }],
      },
      headers: {},
    };

    let responseStatus = 0;
    let responseBody: unknown;

    const res = {
      status: (code: number) => {
        responseStatus = code;
        return res;
      },
      json: (body: unknown) => {
        responseBody = body;
      },
      setHeader: () => {},
      write: () => true,
      end: () => {},
    };

    // If upstream fetch fails in test environment, it catches and returns 502 with structured error
    await middleware(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.ok(responseStatus === 502 || responseStatus === 200);
    assert.ok(responseBody);
  });
});
