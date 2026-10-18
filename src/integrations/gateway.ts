import type { Vela } from '../core/vela.js';
import { createSseTransformer } from '../core/streaming.js';
import { SESSION_HEADER } from '../config/constants.js';
import { VelaError } from '../core/errors.js';
import { detectApiFormat, maskFieldsAsync, maskLlmRequestAsync } from './formats.js';

const STRIP_REQUEST_HEADERS = [
  'host',
  'content-length',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'upgrade',
  'te',
  'trailer',
  'proxy-authorization',
  'proxy-connection',
  'accept-encoding',
  SESSION_HEADER,
];
const STRIP_RESPONSE_HEADERS = ['content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive'];

export interface ForwardRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
  signal?: AbortSignal;
}

export interface ForwardOptions {
  /** Override the upstream API key (sent as x-api-key for Anthropic, Bearer otherwise). */
  apiKey?: string;
  sessionId?: string;
  fetchImpl?: typeof fetch;
}

/** True if this request is an LLM call Vela knows how to mask. */
export function isMaskableLlmRequest(method: string, url: string): boolean {
  if (method.toUpperCase() !== 'POST') return false;
  try {
    return detectApiFormat(new URL(url).pathname) !== null;
  } catch {
    return false;
  }
}

function sanitizeResponseHeaders(h: Headers): Headers {
  const out = new Headers(h);
  for (const k of STRIP_RESPONSE_HEADERS) out.delete(k);
  return out;
}

/** Headers for the upstream request: hop-by-hop and Vela headers removed, API key applied. */
function upstreamHeaders(source: Headers, apiKey: string | undefined, anthropic: boolean): Headers {
  const headers = new Headers(source);
  for (const k of STRIP_REQUEST_HEADERS) headers.delete(k);
  if (apiKey) {
    if (anthropic) {
      headers.delete('authorization');
      headers.set('x-api-key', apiKey);
      if (!headers.has('anthropic-version')) headers.set('anthropic-version', '2023-06-01');
    } else {
      headers.set('authorization', `Bearer ${apiKey}`);
    }
  }
  return headers;
}

/** Restore a JSON (or plain-text) upstream body. */
async function restoreBody(upstream: Response, session: { unmaskValue: <T>(v: T) => T; unmask: (t: string) => { text: string } }): Promise<string> {
  const text = await upstream.text();
  try {
    return JSON.stringify(session.unmaskValue(JSON.parse(text)));
  } catch {
    return session.unmask(text).text;
  }
}

/**
 * Mask an LLM request, forward it upstream and return a Response whose body
 * (JSON or SSE) has every masked value restored. Shared by the fetch
 * interceptor, Express middleware and standalone proxy.
 */
export async function forwardLlmRequest(vela: Vela, req: ForwardRequest, opts: ForwardOptions = {}): Promise<Response> {
  const doFetch = opts.fetchImpl ?? fetch;
  const format = detectApiFormat(new URL(req.url).pathname);
  if (!format || req.method.toUpperCase() !== 'POST' || !req.body) {
    throw new Error('Not a maskable LLM request');
  }
  const body = JSON.parse(req.body) as Record<string, unknown>;

  const sessionId = req.headers.get(SESSION_HEADER) ?? opts.sessionId ?? undefined;
  const session = vela.createSession(sessionId ? { sessionId } : {});
  const payload = await maskLlmRequestAsync(session, format, body);

  const headers = upstreamHeaders(req.headers, opts.apiKey, format === 'anthropic-messages');
  headers.set('content-type', 'application/json');

  const upstream = await doFetch(req.url, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
    ...(req.signal ? { signal: req.signal } : {}),
  });

  const contentType = upstream.headers.get('content-type') ?? '';
  const outHeaders = sanitizeResponseHeaders(upstream.headers);

  if (contentType.includes('text/event-stream') && upstream.body) {
    const transformer = createSseTransformer(format, session);
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    const stream = upstream.body.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          const out = transformer.push(decoder.decode(chunk, { stream: true }));
          if (out) controller.enqueue(encoder.encode(out));
        },
        flush(controller) {
          const out = transformer.push(decoder.decode()) + transformer.end();
          if (out) controller.enqueue(encoder.encode(out));
        },
      }),
    );
    return new Response(stream, { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
  }

  if (contentType.includes('json')) {
    return new Response(await restoreBody(upstream, session), { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
  }

  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
}

/** Write a web Response to a Node ServerResponse-like object. */
export async function pipeResponseToNode(
  response: Response,
  res: {
    writeHead: (status: number, headers: Record<string, string>) => unknown;
    write: (chunk: Uint8Array) => unknown;
    end: () => unknown;
  },
): Promise<void> {
  const headers: Record<string, string> = {};
  response.headers.forEach((v, k) => (headers[k] = v));
  res.writeHead(response.status, headers);
  if (response.body) {
    const reader = response.body.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) res.write(value);
      }
    } finally {
      res.end();
    }
  } else {
    res.end();
  }
}

/** Convert Node's IncomingHttpHeaders to a web Headers object. */
export function nodeHeadersToWeb(h: Record<string, string | string[] | undefined>): Headers {
  const out = new Headers();
  for (const [k, v] of Object.entries(h)) {
    if (v === undefined) continue;
    if (Array.isArray(v)) v.forEach((x) => out.append(k, x));
    else out.set(k, v);
  }
  return out;
}

/**
 * Forward a `fields` route (embeddings, moderations, legacy completions) with
 * its top-level text fields masked, restoring a JSON response. Streaming is
 * rejected for these routes: there is no streaming restorer for them.
 */
export async function forwardFieldsRequest(
  vela: Vela,
  req: ForwardRequest,
  fields: string[],
  opts: ForwardOptions = {},
): Promise<Response> {
  const doFetch = opts.fetchImpl ?? fetch;
  const parsed = JSON.parse(req.body ?? '') as Record<string, unknown>;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new VelaError('Request body must be a JSON object', 400);
  if (parsed.stream === true) throw new VelaError('Streaming is not supported on this route through Vela; nothing was sent', 400);
  const sessionId = req.headers.get(SESSION_HEADER) ?? opts.sessionId ?? undefined;
  const session = vela.createSession(sessionId ? { sessionId } : {});
  const payload = await maskFieldsAsync(session, fields, parsed);

  const headers = upstreamHeaders(req.headers, opts.apiKey, new URL(req.url).hostname === 'api.anthropic.com');
  headers.set('content-type', 'application/json');
  const upstream = await doFetch(req.url, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
    ...(req.signal ? { signal: req.signal } : {}),
  });
  const outHeaders = sanitizeResponseHeaders(upstream.headers);
  if ((upstream.headers.get('content-type') ?? '').includes('json')) {
    return new Response(await restoreBody(upstream, session), { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
  }
  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
}

/**
 * Forward a request upstream untouched (no masking). Used for body-free routes
 * (`GET /v1/models`) and, only when an operator opts in with
 * `passthrough: 'all'`, for routes Vela would otherwise block.
 */
export async function forwardPassthrough(_vela: Vela, req: ForwardRequest, opts: ForwardOptions = {}): Promise<Response> {
  const doFetch = opts.fetchImpl ?? fetch;
  const url = new URL(req.url);
  const headers = upstreamHeaders(req.headers, opts.apiKey, url.hostname === 'api.anthropic.com');
  const upstream = await doFetch(req.url, {
    method: req.method,
    headers,
    ...(req.body !== undefined && !['GET', 'HEAD'].includes(req.method.toUpperCase()) ? { body: req.body } : {}),
    ...(req.signal ? { signal: req.signal } : {}),
  });
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: sanitizeResponseHeaders(upstream.headers),
  });
}
