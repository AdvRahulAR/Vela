import type { Vela } from '../core/vela.js';
import { VelaRouteBlockedError } from '../core/errors.js';
import type { MaskSession } from '../core/session.js';
import { AnthropicStreamUnmasker, ConverseStreamUnmasker, type EventUnmasker } from '../core/streaming.js';
import { maskLlmRequestAsync } from './formats.js';
import { AuditTrail, enforceRequestPolicy } from './gateway.js';
import type { WrapClientOptions } from './openai.js';

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export interface BedrockRuntimeLikeClient {
  send: (command: any, ...rest: any[]) => Promise<any>; // eslint-disable-line @typescript-eslint/no-explicit-any
}

const decoder = new TextDecoder();
const encoder = new TextEncoder();

function bodyText(body: unknown): string {
  if (typeof body === 'string') return body;
  if (body instanceof Uint8Array) return decoder.decode(body);
  throw new VelaRouteBlockedError('SDK', 'InvokeModel', 'request body must be a string or Uint8Array of JSON');
}

/** An InvokeModel response body (the SDK's Uint8ArrayBlobAdapter) as text. */
function responseText(body: unknown): string {
  const b = body as { transformToString?: () => string } | Uint8Array;
  if (b && typeof (b as { transformToString?: unknown }).transformToString === 'function') return (b as { transformToString: () => string }).transformToString();
  return decoder.decode(b as Uint8Array);
}

/** Bytes with the SDK's Uint8ArrayBlobAdapter helper, so callers' transformToString() keeps working. */
function blobLike(text: string): Uint8Array & { transformToString: (encoding?: string) => string } {
  const bytes = encoder.encode(text);
  return Object.assign(bytes, { transformToString: (enc = 'utf-8') => new TextDecoder(enc).decode(bytes) });
}

async function* transform<T>(events: AsyncIterable<T>, map: (ev: T) => T[], end: () => T[], done: () => void): AsyncGenerator<T> {
  for await (const ev of events) yield* map(ev);
  yield* end();
  done();
}

/** Bedrock InvokeModel stream chunks carry Anthropic events as JSON bytes. */
function anthropicChunks(u: EventUnmasker) {
  const wrapEv = (e: Json): Json => ({ chunk: { bytes: encoder.encode(JSON.stringify(e)) } });
  return {
    map: (ev: Json): Json[] => {
      const bytes = ev?.chunk?.bytes;
      if (!bytes) return [ev];
      return u.process(JSON.parse(decoder.decode(bytes))).map(wrapEv);
    },
    end: (): Json[] => u.finish().map(wrapEv),
  };
}

/**
 * Wrap an AWS SDK v3 `BedrockRuntimeClient`. Bedrock requests are SigV4-signed,
 * so they can't be masked by a proxy; this masks them in-process, before the
 * SDK signs them:
 *
 * - `ConverseCommand` and `ConverseStreamCommand`: any model;
 * - `InvokeModelCommand` and `InvokeModelWithResponseStreamCommand`: Anthropic
 *   models (bodies with `anthropic_version`);
 * - every other command (other models' native bodies, CountTokens, async
 *   invoke, guardrails) throws `VelaRouteBlockedError`; `Get*` and `List*` pass.
 *
 * Policy, audit events and the restore policy apply as in the other wrappers.
 */
export function wrapBedrockClient<T extends BedrockRuntimeLikeClient>(client: T, vela: Vela, opts: WrapClientOptions = {}): T {
  const original = client.send.bind(client);
  const wrapped = Object.create(client) as T;
  const endpoint = (): string => {
    const region = (client as { config?: { region?: unknown } }).config?.region;
    return `https://bedrock-runtime.${typeof region === 'string' ? region : 'unknown'}.amazonaws.com`;
  };

  wrapped.send = async (command: Json, ...rest: unknown[]) => {
    const name = String(command?.constructor?.name ?? '');
    if (/^(?:Get|List)\w*Command$/.test(name)) return original(command, ...rest);
    const input: Json = command?.input ?? {};
    const modelId = String(input.modelId ?? 'unknown');
    const Ctor = command.constructor as new (input: Json) => Json;

    const converse = name === 'ConverseCommand' || name === 'ConverseStreamCommand';
    const invoke = name === 'InvokeModelCommand' || name === 'InvokeModelWithResponseStreamCommand';
    if (!converse && !invoke) throw new VelaRouteBlockedError('SDK', name || 'unknown command', 'Vela does not mask this Bedrock command');

    let body: Json | undefined;
    if (invoke) {
      body = JSON.parse(bodyText(input.body)) as Json;
      if (typeof body.anthropic_version !== 'string') {
        throw new VelaRouteBlockedError('SDK', name, 'only Anthropic model bodies can be masked with InvokeModel; use ConverseCommand for other models');
      }
    }
    const sid = typeof opts.sessionId === 'function' ? opts.sessionId(input) : opts.sessionId;
    const route = `/model/${modelId}/${{ ConverseCommand: 'converse', ConverseStreamCommand: 'converse-stream', InvokeModelCommand: 'invoke', InvokeModelWithResponseStreamCommand: 'invoke-with-response-stream' }[name]}`;
    const trail = new AuditTrail(vela, {
      method: 'POST',
      url: endpoint() + route,
      format: converse ? 'bedrock-converse' : 'anthropic-messages',
      model: modelId,
      stableSession: sid !== undefined,
    });
    const session: MaskSession = vela.createSession(sid !== undefined ? { sessionId: sid } : {});

    let result: Json;
    try {
      enforceRequestPolicy(vela, endpoint(), { ...(body ?? input), model: modelId });
      let maskedInput: Json;
      if (converse) {
        maskedInput = await maskLlmRequestAsync(session, 'bedrock-converse', input);
      } else {
        const maskedBody = await maskLlmRequestAsync(session, 'anthropic-messages', body as Json);
        // Keep the caller's body type (bytes or string).
        const json = JSON.stringify(maskedBody);
        maskedInput = { ...input, body: input.body instanceof Uint8Array ? encoder.encode(json) : json };
      }
      await trail.request(session);
      result = await original(new Ctor(maskedInput), ...rest);
    } catch (err) {
      trail.error(err);
      throw err;
    }

    const done = (): void => trail.response(session, Number(result?.$metadata?.httpStatusCode ?? 200));
    if (name === 'ConverseCommand' || name === 'InvokeModelCommand') {
      const out =
        name === 'InvokeModelCommand'
          ? { ...result, body: blobLike(JSON.stringify(session.unmaskValue(JSON.parse(responseText(result.body))))) }
          : session.unmaskValue(result);
      done();
      return out;
    }
    if (name === 'ConverseStreamCommand' && result?.stream) {
      const u = new ConverseStreamUnmasker(session);
      return { ...result, stream: transform(result.stream as AsyncIterable<Json>, (e) => u.process(e), () => u.finish(), done) };
    }
    if (result?.body && Symbol.asyncIterator in result.body) {
      const a = anthropicChunks(new AnthropicStreamUnmasker(session));
      return { ...result, body: transform(result.body as AsyncIterable<Json>, a.map, a.end, done) };
    }
    done();
    return result;
  };
  return wrapped;
}
