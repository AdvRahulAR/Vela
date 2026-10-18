import type { Vela } from '../core/vela.js';
import { createSseTransformer } from '../core/streaming.js';
import { SESSION_HEADER } from '../config/constants.js';
import { VelaAuditError, VelaError, VelaPolicyBlockedError, VelaRouteBlockedError } from '../core/errors.js';
import { globMatch } from '../core/policy.js';
import { newRequestId, type AuditEvent } from '../core/audit.js';
import type { MaskSession } from '../core/session.js';
import { PACKAGE_VERSION } from '../config/constants.js';
import { Logger } from '../utils/logger.js';
import { detectApiFormat, findNonText, maskFieldsAsync, maskLlmRequestAsync } from './formats.js';

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
  'x-vela-key',
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
  /** Authenticated tenant (proxy auth). Recorded in audit events and bound into session ids. */
  tenant?: string;
}

/** Response header carrying the audit request id. */
export const REQUEST_ID_HEADER = 'x-vela-request-id';

const auditLogger = new Logger('vela-audit', true);

/** Model names go into audit events; anything that doesn't look like one is recorded as 'other'. */
const safeModel = (m: unknown): string | undefined =>
  typeof m === 'string' ? (/^[\w.:/@-]{1,128}$/.test(m) ? m : 'other') : undefined;

/**
 * Audit events for one request. `request()` runs before anything is sent and
 * fails closed (VelaAuditError) if the sink throws; later events are best-effort.
 */
export class AuditTrail {
  readonly id = newRequestId();
  private readonly started = Date.now();
  private readonly base: Omit<AuditEvent, 'event' | 'ts'>;
  private done = false;

  constructor(
    private readonly vela: Vela,
    req: { method: string; url: string; format?: string; model?: unknown; tenant?: string; stableSession?: boolean },
  ) {
    const u = new URL(req.url);
    this.base = {
      request_id: this.id,
      vela_version: PACKAGE_VERSION,
      method: req.method.toUpperCase(),
      route: u.pathname,
      upstream: u.host,
      ...(req.format ? { format: req.format } : {}),
      ...(safeModel(req.model) ? { model: safeModel(req.model) } : {}),
      ...(req.tenant ? { tenant: req.tenant } : {}),
      ...(req.stableSession !== undefined ? { session: req.stableSession ? 'stable' : 'random' } : {}),
      ...vela.auditContext,
    };
  }

  private event(e: Partial<AuditEvent> & Pick<AuditEvent, 'event'>): AuditEvent {
    return { ...this.base, ts: new Date().toISOString(), ...e } as AuditEvent;
  }

  /** Before forwarding. Throws VelaAuditError if the sink fails. */
  async request(session: MaskSession): Promise<void> {
    const e = this.event({ event: 'vela.request', ner: session.nerStatus, ...session.stats() });
    this.vela.notify(e);
    const sink = this.vela.audit;
    if (!sink) return;
    try {
      await sink(e);
    } catch (err) {
      throw new VelaAuditError(err);
    }
  }

  /** After the response is complete. */
  response(session: MaskSession, status: number): void {
    this.final({ event: 'vela.response', status, restore: session.restoreReport, latency_ms: Date.now() - this.started });
  }

  /** The request was stopped by an error (never records the message). */
  error(err: unknown): void {
    const status = err instanceof VelaError ? err.status : 502;
    // Route and policy rejections are decisions, not failures.
    const kind = err instanceof VelaRouteBlockedError || err instanceof VelaPolicyBlockedError ? 'vela.blocked' : 'vela.error';
    this.final({ event: kind, status, error_type: err instanceof Error ? err.name : 'Error', latency_ms: Date.now() - this.started });
  }

  private final(e: Partial<AuditEvent> & Pick<AuditEvent, 'event'>): void {
    if (this.done) return;
    this.done = true;
    const ev = this.event(e);
    this.vela.notify(ev);
    const sink = this.vela.audit;
    if (!sink) return;
    Promise.resolve()
      .then(() => sink(ev))
      .catch((err: unknown) => auditLogger.error('audit_sink_failed', err, { request_id: this.id }));
  }
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

/** Headers for the upstream request: hop-by-hop and Vela headers removed, API key applied in the provider's style. */
function upstreamHeaders(source: Headers, apiKey: string | undefined, provider: 'anthropic' | 'gemini' | 'openai'): Headers {
  const headers = new Headers(source);
  for (const k of STRIP_REQUEST_HEADERS) headers.delete(k);
  if (apiKey) {
    if (provider === 'anthropic') {
      headers.delete('authorization');
      headers.set('x-api-key', apiKey);
      if (!headers.has('anthropic-version')) headers.set('anthropic-version', '2023-06-01');
    } else if (provider === 'gemini') {
      headers.delete('authorization');
      headers.set('x-goog-api-key', apiKey);
    } else {
      headers.set('authorization', `Bearer ${apiKey}`);
    }
  }
  return headers;
}

const providerOf = (format: string | null, url: URL): 'anthropic' | 'gemini' | 'openai' =>
  format === 'anthropic-messages' || url.hostname === 'api.anthropic.com'
    ? 'anthropic'
    : format === 'gemini' || url.hostname.endsWith('googleapis.com')
      ? 'gemini'
      : 'openai';

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
  const trail = new AuditTrail(vela, { method: 'POST', url: req.url, format, model: body.model, ...(opts.tenant ? { tenant: opts.tenant } : {}), stableSession: !!sessionId });
  const session = vela.createSession(sessionOptions(sessionId, opts.tenant));
  let upstream: Response;
  try {
    enforceRequestPolicy(vela, req.url, body);
    const payload = await maskLlmRequestAsync(session, format, body);
    await trail.request(session);

    const headers = upstreamHeaders(req.headers, opts.apiKey, providerOf(format, new URL(req.url)));
    headers.set('content-type', 'application/json');

    upstream = await doFetch(req.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      ...(req.signal ? { signal: req.signal } : {}),
    });
  } catch (err) {
    trail.error(err);
    throw err;
  }

  const contentType = upstream.headers.get('content-type') ?? '';
  const outHeaders = sanitizeResponseHeaders(upstream.headers);
  outHeaders.set(REQUEST_ID_HEADER, trail.id);

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
          trail.response(session, upstream.status);
        },
      }),
    );
    return new Response(stream, { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
  }

  if (contentType.includes('json')) {
    const restored = await restoreBody(upstream, session);
    trail.response(session, upstream.status);
    return new Response(restored, { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
  }

  trail.response(session, upstream.status);
  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
}

/**
 * Session options for a request. A caller-chosen session id is bound to the
 * authenticated tenant, so one tenant can't reproduce another's ciphertexts.
 */
function sessionOptions(sessionId: string | undefined, tenant: string | undefined): { sessionId?: string } {
  if (!sessionId) return {};
  return { sessionId: tenant ? `${tenant}\u0000${sessionId}` : sessionId };
}

/**
 * Request-level policy checks, before any masking: provider and model
 * allowlists and non-text content. Throws VelaPolicyBlockedError.
 */
export function enforceRequestPolicy(vela: Vela, url: string | undefined, body: Record<string, unknown>): void {
  const policy = vela.policy;
  if (!policy) return;
  const u = url ? new URL(url) : undefined;
  if (policy.providers && !u) throw new VelaPolicyBlockedError('upstream URL unknown, so providers.allow cannot be checked', 403);
  if (u && policy.providers && !policy.providers.allow.some((p) => globMatch(p, u.host) || globMatch(p, u.hostname) || globMatch(p, u.origin))) {
    throw new VelaPolicyBlockedError(`upstream ${u.host} is not in providers.allow`, 403);
  }
  if (policy.models) {
    const model = typeof body.model === 'string' ? body.model : '';
    if (!policy.models.allow.some((p) => globMatch(p, model))) throw new VelaPolicyBlockedError(`model "${safeModel(model) ?? ''}" is not in models.allow`, 403);
  }
  if (policy.nonText === 'block') {
    const kinds = findNonText(body);
    if (kinds.length) throw new VelaPolicyBlockedError(`non-text content (${kinds.join(', ')}) is blocked`, 422);
  }
}

/** Record a request that was rejected before Vela tried to mask it (a blocked route). */
export function auditBlocked(vela: Vela, method: string, url: string, err: unknown, tenant?: string): void {
  new AuditTrail(vela, { method, url, ...(tenant ? { tenant } : {}) }).error(err);
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
  const trail = new AuditTrail(vela, { method: 'POST', url: req.url, format: 'fields', model: parsed.model, ...(opts.tenant ? { tenant: opts.tenant } : {}), stableSession: !!sessionId });
  const session = vela.createSession(sessionOptions(sessionId, opts.tenant));
  let upstream: Response;
  try {
    enforceRequestPolicy(vela, req.url, parsed);
    const payload = await maskFieldsAsync(session, fields, parsed);
    await trail.request(session);
    const headers = upstreamHeaders(req.headers, opts.apiKey, providerOf(null, new URL(req.url)));
    headers.set('content-type', 'application/json');
    upstream = await doFetch(req.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      ...(req.signal ? { signal: req.signal } : {}),
    });
  } catch (err) {
    trail.error(err);
    throw err;
  }
  const outHeaders = sanitizeResponseHeaders(upstream.headers);
  outHeaders.set(REQUEST_ID_HEADER, trail.id);
  const restored = (upstream.headers.get('content-type') ?? '').includes('json') ? await restoreBody(upstream, session) : null;
  trail.response(session, upstream.status);
  return new Response(restored ?? upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: outHeaders });
}

/**
 * Forward a request upstream untouched (no masking). Used for body-free routes
 * (`GET /v1/models`) and, only when an operator opts in with
 * `passthrough: 'all'`, for routes Vela would otherwise block.
 */
export async function forwardPassthrough(_vela: Vela, req: ForwardRequest, opts: ForwardOptions = {}): Promise<Response> {
  const doFetch = opts.fetchImpl ?? fetch;
  const url = new URL(req.url);
  const headers = upstreamHeaders(req.headers, opts.apiKey, providerOf(null, url));
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
