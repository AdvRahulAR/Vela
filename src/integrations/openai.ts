import type { Vela } from '../core/vela.js';
import { TokenStreamDeMasker } from '../core/streaming.js';
import type {
  MaskResult,
  OpenAIMessage,
  OpenAIRequest,
  OpenAIResponse,
} from '../types.js';

/**
 * Mask all string content in an OpenAI request payload.
 * Recursively inspects text messages and tool call arguments.
 */
export function maskOpenAiRequest(
  vela: Vela,
  request: OpenAIRequest
): { payload: OpenAIRequest; results: MaskResult[] } {
  const results: MaskResult[] = [];

  const clonedMessages: OpenAIMessage[] = request.messages.map((msg) => {
    const newMsg: OpenAIMessage = { ...msg };

    if (typeof msg.content === 'string') {
      const r = vela.mask(msg.content);
      newMsg.content = r.text;
      results.push(r);
    } else if (Array.isArray(msg.content)) {
      newMsg.content = msg.content.map((part) => {
        if (part && typeof part === 'object' && 'type' in part && part.type === 'text' && typeof (part as { text?: unknown }).text === 'string') {
          const textPart = part as { type: 'text'; text: string };
          const r = vela.mask(textPart.text);
          results.push(r);
          return { ...textPart, text: r.text };
        }
        return part;
      });
    }

    if (msg.tool_calls && Array.isArray(msg.tool_calls)) {
      newMsg.tool_calls = msg.tool_calls.map((tc) => {
        if (tc.function?.arguments && typeof tc.function.arguments === 'string') {
          const r = vela.mask(tc.function.arguments);
          results.push(r);
          return {
            ...tc,
            function: {
              ...tc.function,
              arguments: r.text,
            },
          };
        }
        return tc;
      });
    }

    return newMsg;
  });

  const payload: OpenAIRequest = {
    ...request,
    messages: clonedMessages,
  };

  return { payload, results };
}

/**
 * De-mask all string content in an OpenAI response payload.
 */
export function unmaskOpenAiResponse(
  vela: Vela,
  response: OpenAIResponse,
  results: MaskResult[]
): OpenAIResponse {
  if (!response.choices || !Array.isArray(response.choices)) {
    return response;
  }

  const clonedChoices = response.choices.map((choice) => {
    const newChoice = { ...choice };
    const msg = newChoice.message;

    if (msg) {
      const newMsg: OpenAIMessage = { ...msg };

      if (typeof msg.content === 'string') {
        let content = msg.content;
        for (const r of results) {
          content = vela.unmask(content, r).text;
        }
        newMsg.content = content;
      }

      if (msg.tool_calls && Array.isArray(msg.tool_calls)) {
        newMsg.tool_calls = msg.tool_calls.map((tc) => {
          if (tc.function?.arguments && typeof tc.function.arguments === 'string') {
            let args = tc.function.arguments;
            for (const r of results) {
              args = vela.unmask(args, r).text;
            }
            return {
              ...tc,
              function: {
                ...tc.function,
                arguments: args,
              },
            };
          }
          return tc;
        });
      }

      newChoice.message = newMsg;
    }

    return newChoice;
  });

  return {
    ...response,
    choices: clonedChoices,
  };
}

/**
 * Wrap an AsyncIterable stream from OpenAI completions with real-time de-masking.
 */
export async function* unmaskOpenAiStream(
  stream: AsyncIterable<OpenAIResponse>,
  results: MaskResult[]
): AsyncIterable<OpenAIResponse> {
  const deMasker = new TokenStreamDeMasker(results);

  for await (const chunk of stream) {
    if (!chunk.choices || !Array.isArray(chunk.choices)) {
      yield chunk;
      continue;
    }

    const modifiedChoices = chunk.choices.map((choice) => {
      const delta = choice.delta;
      if (delta && typeof delta.content === 'string') {
        const unmaskedContent = deMasker.feed(delta.content);
        return {
          ...choice,
          delta: {
            ...delta,
            content: unmaskedContent,
          },
        };
      }
      return choice;
    });

    yield {
      ...chunk,
      choices: modifiedChoices,
    };
  }

  // Handle remaining buffer on stream completion
  const flushed = deMasker.flush();
  if (flushed) {
    yield {
      id: 'stream-flush',
      object: 'chat.completion.chunk',
      created: Math.floor(Date.now() / 1000),
      choices: [
        {
          index: 0,
          delta: { content: flushed },
          finish_reason: null,
        },
      ],
    };
  }
}

export interface OpenAICompatibleClient {
  chat: {
    completions: {
      create: (params: OpenAIRequest, ...rest: unknown[]) => Promise<unknown> | AsyncIterable<unknown>;
    };
  };
}

/**
 * Wrap an OpenAI SDK client instance so create() automatically masks outbound
 * requests and de-masks inbound responses (supporting both sync and streaming).
 */
export function wrapOpenAiClient<T extends OpenAICompatibleClient>(client: T, vela: Vela): T {
  const originalCreate = client.chat.completions.create.bind(client.chat.completions);

  const wrappedCreate = (async (
    params: OpenAIRequest,
    ...rest: unknown[]
  ): Promise<unknown> => {
    const { payload, results } = maskOpenAiRequest(vela, params);

    const result = await (originalCreate as (...args: unknown[]) => Promise<unknown>)(payload, ...rest);

    // Check if result is an async iterable stream
    if (result && typeof result === 'object' && Symbol.asyncIterator in result) {
      return unmaskOpenAiStream(result as AsyncIterable<OpenAIResponse>, results);
    }

    // Standard single-response completion
    return unmaskOpenAiResponse(vela, result as OpenAIResponse, results);
  }) as typeof client.chat.completions.create;

  // Use prototype delegation to avoid mutating the original client object
  const wrappedCompletions = Object.create(client.chat.completions);
  wrappedCompletions.create = wrappedCreate;

  const wrappedChat = Object.create(client.chat);
  wrappedChat.completions = wrappedCompletions;

  const wrappedClient = Object.create(client);
  wrappedClient.chat = wrappedChat;

  return wrappedClient as T;
}
