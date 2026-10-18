import type { Vela } from '../core/vela.js';
import type { MaskSession } from '../core/session.js';
import { AnthropicStreamUnmasker, toRestoreSource } from '../core/streaming.js';
import { maskLlmRequest, maskLlmRequestAsync } from './formats.js';
import { wrapAsyncIterable, type WrapClientOptions } from './openai.js';
import { blockMethods, overrideMethod } from './wrap-util.js';
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

const ANTHROPIC_BLOCKED: Array<[string, string]> = [
  ['messages.stream', 'use create({ stream: true }) instead of the stream() helper'],
  ['messages.batches.create', 'batch results arrive later and cannot be restored'],
  ['beta.messages.stream', 'use create({ stream: true }) instead of the stream() helper'],
  ['beta.messages.toolRunner', 'use create() and run tools yourself'],
  ['beta.messages.batches.create', 'batch results arrive later and cannot be restored'],
  ['beta.files.upload', 'file uploads cannot be masked'],
];

/**
 * Wrap an Anthropic client. `messages.create` (sync and `stream: true`),
 * `messages.countTokens` and their `beta.messages` equivalents are masked and
 * restored. Methods Vela can't mask (`messages.stream()`, batches, file
 * uploads) throw `VelaRouteBlockedError` instead of sending unmasked text.
 */
export function wrapAnthropicClient<T extends AnthropicCompatibleClient>(client: T, vela: Vela, opts: WrapClientOptions = {}): T {
  const messagesMethod = (original: Fn) => async (params: Json, ...rest: unknown[]) => {
    const sid = typeof opts.sessionId === 'function' ? opts.sessionId(params) : opts.sessionId;
    const session = vela.createSession(sid !== undefined ? { sessionId: sid } : {});
    const payload = await maskLlmRequestAsync(session, 'anthropic-messages', params);
    const result = await original(payload, ...rest);
    if (result && typeof result === 'object' && Symbol.asyncIterator in result) {
      return wrapAsyncIterable(result, new AnthropicStreamUnmasker(session));
    }
    return session.unmaskValue(result);
  };
  let out: T = client;
  for (const path of ['messages.create', 'messages.countTokens', 'beta.messages.create', 'beta.messages.countTokens']) {
    out = overrideMethod(out, path.split('.'), messagesMethod);
  }
  return blockMethods(out, ANTHROPIC_BLOCKED);
}
