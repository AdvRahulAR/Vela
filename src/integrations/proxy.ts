import { VelaError, VelaRouteBlockedError } from '../core/errors.js';
import { createServer, type IncomingMessage, type RequestListener, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createHash, timingSafeEqual } from 'node:crypto';
import type { Vela } from '../core/vela.js';
import { DEFAULT_ANTHROPIC_URL, DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT, DEFAULT_UPSTREAM_URL, PACKAGE_VERSION } from '../config/constants.js';
import { Logger } from '../utils/logger.js';
import { classifyRoute, detectApiFormat } from './formats.js';
import { auditBlocked, forwardFieldsRequest, forwardLlmRequest, forwardPassthrough, nodeHeadersToWeb, pipeResponseToNode } from './gateway.js';
import type { ProxyServerOptions } from '../types.js';

function sendJson(res: import('node:http').ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

/** `true` (the pre-0.4.1 opt-in) means 'all'; `false` means 'none'; default 'safe'. */
export function normalizePassthrough(p: ProxyServerOptions['passthrough']): 'safe' | 'all' | 'none' {
  if (p === true) return 'all';
  if (p === false) return 'none';
  return p ?? 'safe';
}

/** Header carrying a proxy client token (stripped before forwarding). */
export const AUTH_HEADER = 'x-vela-key';

const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);

const digest = (s: string): Buffer => createHash('sha256').update(s).digest();

/** Constant-time token lookup: returns the tenant for a valid token. */
function makeAuthenticator(tokens: Record<string, string>): (req: IncomingMessage) => string | null {
  const entries = Object.entries(tokens).map(([token, tenant]) => ({ d: digest(token), tenant }));
  return (req) => {
    const raw = req.headers[AUTH_HEADER];
    const given = typeof raw === 'string' ? raw : '';
    if (!given) return null;
    const d = digest(given);
    let tenant: string | null = null;
    // Compare against every token so timing doesn't reveal which one matched.
    for (const e of entries) if (timingSafeEqual(d, e.d)) tenant = e.tenant;
    return tenant;
  };
}

/** Per-client token bucket: `perMinute` requests, refilled continuously. */
function makeRateLimiter(perMinute: number): (client: string) => number {
  const buckets = new Map<string, { tokens: number; at: number }>();
  return (client) => {
    const now = Date.now();
    const b = buckets.get(client) ?? { tokens: perMinute, at: now };
    b.tokens = Math.min(perMinute, b.tokens + ((now - b.at) / 60_000) * perMinute);
    b.at = now;
    buckets.set(client, b);
    if (buckets.size > 10_000) buckets.delete(buckets.keys().next().value as string);
    if (b.tokens < 1) return Math.ceil(((1 - b.tokens) / perMinute) * 60);
    b.tokens -= 1;
    return 0;
  };
}

/**
 * Standalone privacy proxy. Point an OpenAI or Anthropic SDK's base URL at it.
 * Binds to 127.0.0.1 by default — pass `host: '0.0.0.0'` only if you really
 * intend to expose it (it forwards requests with the caller's credentials).
 */
export function runProxy(vela: Vela, opts: ProxyServerOptions = {}): Server {
  const port = opts.port ?? DEFAULT_PROXY_PORT;
  const host = opts.host ?? DEFAULT_PROXY_HOST;
  const upstream = (opts.upstream ?? DEFAULT_UPSTREAM_URL).replace(/\/+$/, '');
  // Without an explicit upstream, Anthropic requests (Messages paths, or any request carrying
  // Anthropic's headers, e.g. GET /v1/models from the Anthropic SDK) go to api.anthropic.com.
  const upstreamFor = (path: string, headers: import('node:http').IncomingHttpHeaders): string =>
    !opts.upstream && (detectApiFormat(path) === 'anthropic-messages' || headers['anthropic-version'] !== undefined)
      ? DEFAULT_ANTHROPIC_URL
      : upstream;
  const maxBody = opts.maxBodySizeBytes ?? 10 * 1024 * 1024;
  const logger = new Logger('vela-proxy', true);
  const passthrough = normalizePassthrough(opts.passthrough);
  const authenticate = opts.authTokens && Object.keys(opts.authTokens).length ? makeAuthenticator(opts.authTokens) : null;
  if (!authenticate && !LOOPBACK.has(host) && !opts.insecure) {
    throw new VelaError(
      `Refusing to listen on ${host} without authentication. Set authTokens (--auth-token-file), or insecure: true (--insecure) if something in front of Vela authenticates clients.`,
      500,
    );
  }
  const limit = opts.rateLimitPerMinute ? makeRateLimiter(opts.rateLimitPerMinute) : null;

  const handler: RequestListener = async (req, res) => {
    const rawUrl = req.url ?? '/';
    const urlPath = rawUrl.split('?')[0] ?? '/';
    const isHealth = req.method === 'GET' && (urlPath === '/health' || urlPath === '/');

    let tenant: string | undefined;
    if (authenticate && !isHealth) {
      const t = authenticate(req);
      if (t === null) {
        req.resume();
        sendJson(res, 401, { error: { message: `Missing or invalid ${AUTH_HEADER} header`, type: 'vela_unauthorized' } });
        return;
      }
      tenant = t;
    }
    if (limit && !isHealth) {
      const wait = limit(tenant ?? req.socket.remoteAddress ?? 'unknown');
      if (wait > 0) {
        req.resume();
        res.setHeader('retry-after', String(wait));
        sendJson(res, 429, { error: { message: 'Rate limit exceeded', type: 'vela_rate_limited' } });
        return;
      }
    }

    if (isHealth) {
      sendJson(res, 200, {
        status: 'healthy',
        service: 'vela-privacy-gateway',
        uptime_seconds: process.uptime(),
        version: PACKAGE_VERSION,
      });
      return;
    }

    const method = (req.method ?? 'GET').toUpperCase();
    const route = classifyRoute(method, urlPath);
    if (route.kind === 'safe' && passthrough === 'none') {
      sendJson(res, 404, { error: { message: `Route ${method} ${urlPath} not found` } });
      return;
    }
    if (route.kind === 'blocked' && passthrough !== 'all') {
      req.resume();
      const err = new VelaRouteBlockedError(method, urlPath, route.reason);
      logger.warn('proxy_route_blocked', { method, urlPath });
      auditBlocked(vela, method, upstreamFor(urlPath, req.headers) + urlPath, err, tenant);
      sendJson(res, err.status, { error: { message: err.message, type: 'vela_route_blocked' } });
      return;
    }

    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      const b = chunk as Buffer;
      size += b.length;
      if (size > maxBody) {
        sendJson(res, 413, { error: { message: `Payload too large. Exceeds limit of ${maxBody} bytes.` } });
        req.destroy();
        return;
      }
      chunks.push(b);
    }
    const body = Buffer.concat(chunks).toString('utf8');

    if (route.kind === 'llm' || route.kind === 'fields') {
      try {
        JSON.parse(body);
      } catch {
        sendJson(res, 400, { error: { message: 'Invalid JSON payload' } });
        return;
      }
    }

    const start = Date.now();
    const controller = new AbortController();
    res.on('close', () => {
      if (!res.writableEnded) controller.abort();
    });
    const forward = {
      url: upstreamFor(urlPath, req.headers) + rawUrl,
      method,
      headers: nodeHeadersToWeb(req.headers),
      // Body-free methods never forward a body, so nothing can ride along unmasked.
      ...(body && route.kind !== 'safe' ? { body } : {}),
      signal: controller.signal,
    };
    const fwdOpts = { ...(opts.apiKey ? { apiKey: opts.apiKey } : {}), ...(tenant ? { tenant } : {}) };
    try {
      const response =
        route.kind === 'llm'
          ? await forwardLlmRequest(vela, forward, fwdOpts)
          : route.kind === 'fields'
            ? await forwardFieldsRequest(vela, forward, route.fields, fwdOpts)
            : await forwardPassthrough(vela, forward, fwdOpts);
      await pipeResponseToNode(response, res);
      if (route.kind !== 'safe') logger.info('proxy_request', { urlPath, route: route.kind, status: response.status }, Date.now() - start);
    } catch (err) {
      logger.error('proxy_request_error', err, { urlPath });
      if (res.headersSent) {
        res.end();
        return;
      }
      if (err instanceof VelaError) {
        sendJson(res, err.status, { error: { message: err.message, type: 'vela_error' } });
        return;
      }
      const msg = err instanceof Error ? err.message : 'Unknown proxy error';
      sendJson(res, 502, { error: { message: `Vela gateway proxy failure: ${msg}`, type: 'gateway_error' } });
    }
  };
  const server: Server = opts.tls ? (createHttpsServer({ cert: opts.tls.cert, key: opts.tls.key }, handler) as unknown as Server) : createServer(handler);

  server.listen(port, host, () => {
    const shown = host.includes(':') ? `[${host}]` : host;
    logger.info('server_started', { host, port, upstream });
    /* eslint-disable no-console -- operator-facing startup banner, independent of enableLogging */
    console.log(`[vela] Privacy proxy active on ${opts.tls ? 'https' : 'http'}://${shown}:${port}`);
    if (authenticate) console.log(`[vela] Clients must send ${AUTH_HEADER}: <token>`);
    console.log(`[vela] Forwarding upstream to ${upstream}`);
    if (passthrough === 'all') {
      console.warn('[vela] WARNING: passthrough "all" forwards routes Vela cannot mask (batches, files, unknown endpoints) unmasked.');
    }
    if (!LOOPBACK.has(host) && !authenticate) {
      console.warn('[vela] WARNING: listening beyond loopback with --insecure; anyone who can reach this port can use it.');
    }
    /* eslint-enable no-console */
  });
  return server;
}
