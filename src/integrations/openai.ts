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
import { baseUrlOf, fieldsMethod, guardClient } from './wrap-util.js';
import { enforceRequestPolicy } from './gateway.js';
import type { MaskResult, OpenAIRequest, OpenAIResponse, SessionOptions } from '../types.js';

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Fn = (...args: any[]) => any; // eslint-disable-line @typescript-eslint/no-explicit-any

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

/** Why common methods are blocked (any method not wrapped or read-only is blocked). */
const OPENAI_REASONS: Record<string, string> = {
  'chat.completions.stream': 'use create({ stream: true }) instead of the stream() helper',
  'chat.completions.runTools': 'use create() and run tools yourself',
  'responses.stream': 'use create({ stream: true }) instead of the stream() helper',
  'batches.create': 'batch results arrive later and cannot be restored',
  'files.create': 'file uploads cannot be masked',
  'uploads.create': 'file uploads cannot be masked',
  'audio.speech.create': 'audio cannot be masked',
  'audio.transcriptions.create': 'audio cannot be masked',
  'images.generate': 'image prompts are not masked',
  'beta.threads.messages.create': 'Assistants threads cannot be restored',
};

/**
 * Wrap an OpenAI client. Masked on the way out and restored on the way in:
 * `chat.completions.create`/`parse` and `responses.create`/`parse` (sync and
 * streaming), `responses.inputTokens.count`, `completions.create`,
 * `embeddings.create` and `moderations.create`. Read-only methods (`list`,
 * `retrieve`, `del`, `cancel`…) pass through. Every other method (`batches.create`,
 * `files.create`, the `stream()` helpers, Assistants, raw `client.post`…)
 * throws `VelaRouteBlockedError` instead of sending unmasked text.
 */
export function wrapOpenAiClient<T extends OpenAICompatibleClient>(client: T, vela: Vela, opts: WrapClientOptions = {}): T {
  const sessionFor = (params: Json): MaskSession => {
    const sid = resolveSessionId(opts.sessionId, params);
    return vela.createSession(sid !== undefined ? { sessionId: sid } : {});
  };
  const chatMethod = (original: Fn) => async (params: OpenAIRequest, ...rest: unknown[]) => {
    const session = sessionFor(params);
    enforceRequestPolicy(vela, baseUrlOf(client), params);
    const payload = await maskLlmRequestAsync(session, 'openai-chat', params);
    const result = await original(payload, ...rest);
    if (isAsyncIterable(result)) return wrapAsyncIterable(result, new OpenAiChatStreamUnmasker(session));
    return session.unmaskValue(result);
  };
  const responsesMethod = (original: Fn) => async (params: Json, ...rest: unknown[]) => {
    const session = sessionFor(params);
    enforceRequestPolicy(vela, baseUrlOf(client), params);
    const payload = await maskLlmRequestAsync(session, 'openai-responses', params);
    const result = await original(payload, ...rest);
    if (isAsyncIterable(result)) return wrapAsyncIterable(result, new ResponsesStreamUnmasker(session));
    return session.unmaskValue(result);
  };
  const fields = (f: string[]) => fieldsMethod(vela, f, (p) => resolveSessionId(opts.sessionId, p), baseUrlOf(client));

  return guardClient(
    client,
    {
      'chat.completions.create': chatMethod,
      'chat.completions.parse': chatMethod,
      'beta.chat.completions.parse': chatMethod,
      'responses.create': responsesMethod,
      'responses.parse': responsesMethod,
      'responses.inputTokens.count': responsesMethod,
      'completions.create': fields(['prompt', 'suffix']),
      'embeddings.create': fields(['input']),
      'moderations.create': fields(['input']),
    },
    OPENAI_REASONS,
  );
}

export type { RestoreSource };
