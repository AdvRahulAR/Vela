import type { Vela } from '../core/vela.js';
import type { MaskSession } from '../core/session.js';
import { AnthropicStreamUnmasker, toRestoreSource } from '../core/streaming.js';
import { maskLlmRequest, maskLlmRequestAsync } from './formats.js';
import { wrapAsyncIterable, type WrapClientOptions } from './openai.js';
import { baseUrlOf, fieldsMethod, guardClient } from './wrap-util.js';
import { enforceRequestPolicy } from './gateway.js';
import type { MaskResult, SessionOptions } from '../types.js';

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Fn = (...args: any[]) => any; // eslint-disable-line @typescript-eslint/no-explicit-any

/**
 * Mask an Anthropic Messages API request: `system` (string or blocks), message
 * text blocks, tool_use inputs, tool_result contents and plain-text documents.
 */
export function maskAnthropicRequest<T extends object>(
  vela: Vela,
  request: T,
  opts: SessionOptions & { session?: MaskSession } = {},
): { payload: T; results: MaskResult[]; session: MaskSession } {
  const session = opts.session ?? vela.createSession(opts);
  const payload = maskLlmRequest(session, 'anthropic-messages', request);
  return { payload, results: [session.toResult()], session };
}

/** maskAnthropicRequest() that first runs any configured async recognizers (NER services). */
export async function maskAnthropicRequestAsync<T extends object>(
  vela: Vela,
  request: T,
  opts: SessionOptions & { session?: MaskSession } = {},
): Promise<{ payload: T; results: MaskResult[]; session: MaskSession }> {
  const session = opts.session ?? vela.createSession(opts);
    const payload = await maskLlmRequestAsync(session, 'anthropic-messages', request);
  return { payload, results: [session.toResult()], session };
}

/** Restore originals in an Anthropic Messages response (text, tool_use input, thinking…). */
export function unmaskAnthropicResponse<T>(response: T, source: MaskSession | MaskResult | MaskResult[]): T {
  return toRestoreSource(source).unmaskValue(response);
}

/** De-mask an Anthropic streaming event iterable (`messages.create({ stream: true })`). */
export async function* unmaskAnthropicStream(
  stream: AsyncIterable<Json>,
  source: MaskSession | MaskResult | MaskResult[],
): AsyncGenerator<Json> {
  const u = new AnthropicStreamUnmasker(toRestoreSource(source));
  for await (const ev of stream) for (const out of u.process(ev)) yield out;
  for (const out of u.finish()) yield out;
}

export interface AnthropicCompatibleClient {
  messages: {
    create: (params: any, ...rest: any[]) => Promise<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  };
}

const ANTHROPIC_REASONS: Record<string, string> = {
  'messages.stream': 'use create({ stream: true }) instead of the stream() helper',
  'messages.batches.create': 'batch results arrive later and cannot be restored',
  'beta.messages.stream': 'use create({ stream: true }) instead of the stream() helper',
  'beta.messages.batches.create': 'batch results arrive later and cannot be restored',
  'beta.files.upload': 'file uploads cannot be masked',
};

/**
 * Wrap an Anthropic client. `messages.create` (sync and `stream: true`),
 * `messages.countTokens`, their `beta.messages` equivalents and legacy
 * `completions.create` are masked and restored. Read-only methods pass. Every
 * other method (`messages.stream()`, batches, file uploads, raw `client.post`…)
 * throws `VelaRouteBlockedError` instead of sending unmasked text.
 */
export function wrapAnthropicClient<T extends AnthropicCompatibleClient>(client: T, vela: Vela, opts: WrapClientOptions = {}): T {
  const sid = (params: Json) => (typeof opts.sessionId === 'function' ? opts.sessionId(params) : opts.sessionId);
  const messagesMethod = (original: Fn) => async (params: Json, ...rest: unknown[]) => {
    const id = sid(params);
    const session = vela.createSession(id !== undefined ? { sessionId: id } : {});
    enforceRequestPolicy(vela, baseUrlOf(client), params);
    const payload = await maskLlmRequestAsync(session, 'anthropic-messages', params);
    const result = await original(payload, ...rest);
    if (result && typeof result === 'object' && Symbol.asyncIterator in result) {
      return wrapAsyncIterable(result, new AnthropicStreamUnmasker(session));
    }
    return session.unmaskValue(result);
  };
  return guardClient(
    client,
    {
      'messages.create': messagesMethod,
      'messages.countTokens': messagesMethod,
      'beta.messages.create': messagesMethod,
      'beta.messages.countTokens': messagesMethod,
      'completions.create': fieldsMethod(vela, ['prompt'], sid, baseUrlOf(client)),
    },
    ANTHROPIC_REASONS,
  );
}
