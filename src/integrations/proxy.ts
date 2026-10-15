import { VelaError } from '../core/errors.js';
import { createServer, type Server } from 'node:http';
import type { Vela } from '../core/vela.js';
import { DEFAULT_ANTHROPIC_URL, DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT, DEFAULT_UPSTREAM_URL, PACKAGE_VERSION } from '../config/constants.js';
import { Logger } from '../utils/logger.js';
import { detectApiFormat } from './formats.js';
import { isEmbeddingsPath, forwardLlmRequest, forwardPassthrough, nodeHeadersToWeb, pipeResponseToNode } from './gateway.js';
import type { ProxyServerOptions } from '../types.js';

function sendJson(res: import('node:http').ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
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
  const upstreamFor = (path: string): string =>
    !opts.upstream && detectApiFormat(path) === 'anthropic-messages' ? DEFAULT_ANTHROPIC_URL : upstream;
  const maxBody = opts.maxBodySizeBytes ?? 10 * 1024 * 1024;
  const logger = new Logger('vela-proxy', true);

  const server = createServer(async (req, res) => {
    const rawUrl = req.url ?? '/';
    const urlPath = rawUrl.split('?')[0] ?? '/';

    if (req.method === 'GET' && (urlPath === '/health' || urlPath === '/')) {
      sendJson(res, 200, {
        status: 'healthy',
        service: 'vela-privacy-gateway',
        uptime_seconds: process.uptime(),
        version: PACKAGE_VERSION,
      });
      return;
    }

    const isLlmRoute = req.method === 'POST' && detectApiFormat(urlPath) !== null;
    if (!isLlmRoute && opts.passthrough === false) {
      sendJson(res, 404, { error: { message: `Route ${req.method} ${urlPath} not found` } });
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

    if (!isLlmRoute) {
      const controller = new AbortController();
      res.on('close', () => {
        if (!res.writableEnded) controller.abort();
      });
      try {
        const method = req.method ?? 'GET';
        const payload: string | undefined = body || undefined;
        if (payload && method === 'POST' && isEmbeddingsPath(urlPath)) JSON.parse(payload);
        const response = await forwardPassthrough(
          vela,
          {
            url: upstream + rawUrl,
            method,
            headers: nodeHeadersToWeb(req.headers),
            ...(payload !== undefined ? { body: payload } : {}),
            signal: controller.signal,
          },
          opts.apiKey ? { apiKey: opts.apiKey } : {},
        );
        await pipeResponseToNode(response, res);
      } catch (err) {
        if (res.headersSent) {
          res.end();
          return;
        }
        if (err instanceof SyntaxError) {
          sendJson(res, 400, { error: { message: 'Invalid JSON payload' } });
          return;
        }
        const msg = err instanceof Error ? err.message : 'Unknown proxy error';
        sendJson(res, 502, { error: { message: `Vela gateway proxy failure: ${msg}`, type: 'gateway_error' } });
      }
      return;
    }

    try {
      JSON.parse(body);
    } catch {
      sendJson(res, 400, { error: { message: 'Invalid JSON payload' } });
      return;
    }

    const start = Date.now();
    const controller = new AbortController();
    res.on('close', () => {
      if (!res.writableEnded) controller.abort();
    });
    try {
      const response = await forwardLlmRequest(
        vela,
        {
          url: upstreamFor(urlPath) + rawUrl,
          method: 'POST',
          headers: nodeHeadersToWeb(req.headers),
          body,
          signal: controller.signal,
        },
        opts.apiKey ? { apiKey: opts.apiKey } : {},
      );
      await pipeResponseToNode(response, res);
      logger.info('proxy_request', { urlPath, status: response.status }, Date.now() - start);
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
  });

  server.listen(port, host, () => {
    const shown = host.includes(':') ? `[${host}]` : host;
    logger.info('server_started', { host, port, upstream });
    /* eslint-disable no-console -- operator-facing startup banner, independent of enableLogging */
    console.log(`[vela] Privacy proxy active on http://${shown}:${port}`);
    console.log(`[vela] Forwarding upstream to ${upstream}`);
    if (host === '0.0.0.0' || host === '::') {
      console.warn('[vela] WARNING: listening on all interfaces — anyone who can reach this port can use it.');
    }
    /* eslint-enable no-console */
  });
  return server;
}
