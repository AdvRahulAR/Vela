import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Vela } from '../core/vela.js';
import { DEFAULT_PROXY_PORT, DEFAULT_UPSTREAM_URL, LLM_REQUEST_PATHS, PACKAGE_VERSION } from '../config/constants.js';
import { maskOpenAiRequest, unmaskOpenAiResponse } from './openai.js';
import { createSseDeMasker } from '../core/streaming.js';
import { Logger } from '../utils/logger.js';
import type { OpenAIRequest, OpenAIResponse, ProxyServerOptions } from '../types.js';

/**
 * Launch a standalone OpenAI-compatible proxy server with health checks,
 * streaming SSE support, and structured telemetry.
 */
export function runProxy(vela: Vela, opts: ProxyServerOptions = {}): Server {
  const port = opts.port ?? DEFAULT_PROXY_PORT;
  const upstream = opts.upstream ?? DEFAULT_UPSTREAM_URL;
  const logger = new Logger('vela-proxy', true);

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const urlPath = req.url?.split('?')[0] ?? '';

    // Health check endpoint
    if (req.method === 'GET' && (urlPath === '/health' || urlPath === '/')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'healthy',
          service: 'vela-privacy-gateway',
          uptime_seconds: process.uptime(),
          version: PACKAGE_VERSION,
        })
      );
      return;
    }

    const isCompletion =
      req.method === 'POST' &&
      LLM_REQUEST_PATHS.some((p) => urlPath === p || urlPath.endsWith(p));

    if (!isCompletion) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: `Route ${req.method} ${urlPath} not found` } }));
      return;
    }

    // Read request body with memory limit protection (default 10MB)
    const maxBodySize = opts.maxBodySizeBytes ?? 10 * 1024 * 1024;
    let raw = '';
    let exceeded = false;

    for await (const chunk of req) {
      raw += chunk;
      if (raw.length > maxBodySize) {
        exceeded = true;
        break;
      }
    }

    if (exceeded) {
      res.writeHead(413, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: `Payload too large. Exceeds limit of ${maxBodySize} bytes.` } }));
      return;
    }

    let body: OpenAIRequest;
    try {
      body = JSON.parse(raw) as OpenAIRequest;
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'Invalid JSON payload' } }));
      return;
    }

    const startTime = Date.now();
    try {
      const { payload, results } = maskOpenAiRequest(vela, body);
      const upstreamUrl = upstream.replace(/\/+$/, '') + urlPath;

      const headers: Record<string, string> = {
        'content-type': 'application/json',
      };

      const authHeader = req.headers['authorization'];
      if (opts.apiKey) {
        headers['authorization'] = `Bearer ${opts.apiKey}`;
      } else if (typeof authHeader === 'string') {
        headers['authorization'] = authHeader;
      }

      const upstreamRes = await fetch(upstreamUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      });

      const contentType = upstreamRes.headers.get('content-type') || '';

      // Streaming Server-Sent Events response
      if (contentType.includes('text/event-stream') && upstreamRes.body) {
        res.writeHead(upstreamRes.status, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
          connection: 'keep-alive',
        });

        const deMasker = createSseDeMasker(results);
        const reader = upstreamRes.body.getReader();
        const decoder = new TextDecoder();

        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            const textChunk = decoder.decode(value, { stream: true });
            const unmaskedChunk = deMasker(textChunk);
            if (unmaskedChunk) {
              res.write(unmaskedChunk);
            }
          }
        } finally {
          res.end();
        }

        logger.info('proxy_streaming_request', { urlPath }, Date.now() - startTime);
        return;
      }

      // Standard JSON response
      if (contentType.includes('application/json')) {
        const json = (await upstreamRes.json()) as OpenAIResponse;
        const unmasked = unmaskOpenAiResponse(vela, json, results);

        res.writeHead(upstreamRes.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(unmasked));
        logger.info('proxy_json_request', { urlPath, status: upstreamRes.status }, Date.now() - startTime);
        return;
      }

      // Pass-through for other responses
      const buffer = await upstreamRes.arrayBuffer();
      res.writeHead(upstreamRes.status, { 'content-type': contentType });
      res.end(Buffer.from(buffer));
    } catch (err: unknown) {
      logger.error('proxy_request_error', err, { urlPath });
      const errorMsg = err instanceof Error ? err.message : 'Unknown proxy error';
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          error: {
            message: `Vela gateway proxy failure: ${errorMsg}`,
            type: 'gateway_error',
          },
        })
      );
    }
  });

  server.listen(port, () => {
    logger.info('server_started', {
      port,
      upstream,
      endpoint: `http://127.0.0.1:${port}/v1`,
    });
    console.log(`[vela] Privacy proxy active on http://127.0.0.1:${port}`);
    console.log(`[vela] Forwarding upstream to ${upstream}`);
    console.log(`[vela] Set OPENAI_BASE_URL=http://127.0.0.1:${port}/v1`);
  });

  return server;
}
