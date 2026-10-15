import type { Vela } from '../core/vela.js';
import { MaskSession } from '../core/session.js';
import {
  OpenAiChatStreamUnmasker,
  ResponsesStreamUnmasker,
  toRestoreSource,
  type EventUnmasker,
  type RestoreSource,
} from '../core/streaming.js';
import { maskLlmRequest, maskLlmRequestAsync } from './formats.js';
import type { MaskResult, OpenAIRequest, OpenAIResponse, SessionOptions } from '../types.js';

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/**
 * Mask an OpenAI Chat Completions request (all messages, system prompts,
 * text parts and tool-call arguments) within ONE session, so placeholders are
 * unique across messages.
 */
export function maskOpenAiRequest(
  vela: Vela,
  request: OpenAIRequest,
  opts: SessionOptions & { session?: MaskSession } = {},
): { payload: OpenAIRequest; results: MaskResult[]; session: MaskSession } {
  const session = opts.session ?? vela.createSession(opts);
  const payload = maskLlmRequest(session, 'openai-chat', request);
  return { payload, results: [session.toResult()], session };
}

/** Mask an OpenAI Responses API request (`instructions`, `input` items, function call args/outputs). */
export function maskOpenAiResponsesRequest<T extends object>(
  vela: Vela,
  request: T,
  opts: SessionOptions & { session?: MaskSession } = {},
): { payload: T; results: MaskResult[]; session: MaskSession } {
  const session = opts.session ?? vela.createSession(opts);
  const payload = maskLlmRequest(session, 'openai-responses', request);
  return { payload, results: [session.toResult()], session };
}

/** maskOpenAiRequest() that first runs any configured async recognizers (NER services). */
export async function maskOpenAiRequestAsync(
  vela: Vela,
  request: OpenAIRequest,
  opts: SessionOptions & { session?: MaskSession } = {},
): Promise<{ payload: OpenAIRequest; results: MaskResult[]; session: MaskSession }> {
  const session = opts.session ?? vela.createSession(opts);
  const payload = await maskLlmRequestAsync(session, 'openai-chat', request);
  return { payload, results: [session.toResult()], session };
}

/** maskOpenAiResponsesRequest() that first runs any configured async recognizers (NER services). */
export async function maskOpenAiResponsesRequestAsync<T extends object>(
  vela: Vela,
  request: T,
  opts: SessionOptions & { session?: MaskSession } = {},
): Promise<{ payload: T; results: MaskResult[]; session: MaskSession }> {
  const session = opts.session ?? vela.createSession(opts);
  const payload = await maskLlmRequestAsync(session, 'openai-responses', request);
  return { payload, results: [session.toResult()], session };
}

/**
 * Restore originals everywhere in a (Chat Completions or Responses API) response:
 * message content, refusals, tool-call arguments (JSON-escaped), output items…
 */
export function unmaskOpenAiResponse<T = OpenAIResponse>(
  _vela: Vela,
  response: T,
  source: MaskSession | MaskResult | MaskResult[],
): T {
  return toRestoreSource(source).unmaskValue(response);
}

async function* transformStream(
  stream: AsyncIterable<Json>,
  unmasker: EventUnmasker,
): AsyncGenerator<Json> {
  for await (const ev of stream) {
    for (const out of unmasker.process(ev)) yield out;
  }
  for (const out of unmasker.finish()) yield out;
}

/** De-mask a Chat Completions chunk stream (per choice, per tool call, chunk-boundary aware). */
export function unmaskOpenAiStream(
  stream: AsyncIterable<Json>,
  source: MaskSession | MaskResult | MaskResult[],
): AsyncGenerator<Json> {
  return transformStream(stream, new OpenAiChatStreamUnmasker(toRestoreSource(source)));
}

/** De-mask a Responses API event stream. */
export function unmaskOpenAiResponsesStream(
  stream: AsyncIterable<Json>,
  source: MaskSession | MaskResult | MaskResult[],
): AsyncGenerator<Json> {
  return transformStream(stream, new ResponsesStreamUnmasker(toRestoreSource(source)));
}

/**
 * Wrap a streaming result so iteration is de-masked while the SDK's own Stream
 * helpers (toReadableStream, controller, …) keep working.
 */
export function wrapAsyncIterable<S extends object>(stream: S, unmasker: EventUnmasker): S {
  const wrapped = Object.create(stream) as S & { [Symbol.asyncIterator]: () => AsyncIterator<Json> };
  Object.defineProperty(wrapped, Symbol.asyncIterator, {
    value: () => transformStream(stream as unknown as AsyncIterable<Json>, unmasker)[Symbol.asyncIterator](),
  });
  return wrapped;
}

export interface OpenAICompatibleClient {
  chat: {
    completions: {
      create: (params: any, ...rest: any[]) => Promise<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
    };
  };
  responses?: {
    create: (params: any, ...rest: any[]) => Promise<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  };
}

export interface WrapClientOptions {
  /** Stable session id per call (e.g. conversation id) — keeps masking consistent across turns. */
  sessionId?: string | ((params: Json) => string | undefined);
}

function resolveSessionId(opt: WrapClientOptions['sessionId'], params: Json): string | undefined {
  return typeof opt === 'function' ? opt(params) : opt;
}

function isAsyncIterable(x: unknown): x is AsyncIterable<Json> {
  return !!x && typeof x === 'object' && Symbol.asyncIterator in x;
}

/**
 * Wrap an OpenAI client: `chat.completions.create` and `responses.create`
 * (sync and streaming) are masked on the way out and restored on the way in.
 */
export function wrapOpenAiClient<T extends OpenAICompatibleClient>(client: T, vela: Vela, opts: WrapClientOptions = {}): T {
  const originalCreate = client.chat.completions.create.bind(client.chat.completions);
  const wrappedCompletions = Object.create(client.chat.completions);
  wrappedCompletions.create = async (params: OpenAIRequest, ...rest: unknown[]) => {
    const sid = resolveSessionId(opts.sessionId, params);
    const session = vela.createSession(sid !== undefined ? { sessionId: sid } : {});
    const payload = await maskLlmRequestAsync(session, 'openai-chat', params);
    const result = await originalCreate(payload, ...rest);
    if (isAsyncIterable(result)) return wrapAsyncIterable(result, new OpenAiChatStreamUnmasker(session));
    return session.unmaskValue(result);
  };
  const wrappedChat = Object.create(client.chat);
  wrappedChat.completions = wrappedCompletions;
  const wrappedClient = Object.create(client);
  wrappedClient.chat = wrappedChat;

  if (client.responses && typeof client.responses.create === 'function') {
    const originalResponses = client.responses.create.bind(client.responses);
    const wrappedResponses = Object.create(client.responses);
    wrappedResponses.create = async (params: Json, ...rest: unknown[]) => {
      const sid = resolveSessionId(opts.sessionId, params);
      const session = vela.createSession(sid !== undefined ? { sessionId: sid } : {});
      const payload = await maskLlmRequestAsync(session, 'openai-responses', params);
      const result = await originalResponses(payload, ...rest);
      if (isAsyncIterable(result)) return wrapAsyncIterable(result, new ResponsesStreamUnmasker(session));
      return session.unmaskValue(result);
    };
    wrappedClient.responses = wrappedResponses;
  }
  return wrappedClient as T;
}

export type { RestoreSource };
