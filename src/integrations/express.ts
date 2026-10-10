import type { Vela } from '../core/vela.js';
import { DEFAULT_ANTHROPIC_URL, DEFAULT_UPSTREAM_URL } from '../config/constants.js';
import { detectApiFormat } from './formats.js';
import { forwardLlmRequest, nodeHeadersToWeb, pipeResponseToNode } from './gateway.js';
import type { ExpressMiddlewareOptions } from '../types.js';

export interface MinimalRequest {
  path: string;
  /** Path + query relative to the mount point (Express `req.url`). */
  url?: string;
  method?: string;
  body?: unknown;
  headers: Record<string, string | string[] | undefined>;
}

export interface MinimalResponse {
  on?: (event: 'close', cb: () => void) => unknown;
  writableEnded?: boolean;
  status: (code: number) => MinimalResponse;
  json: (body: unknown) => void;
  setHeader: (name: string, value: string) => void;
  write: (chunk: unknown) => boolean;
  end: () => void;
  writeHead?: (status: number, headers: Record<string, string>) => unknown;
  headersSent?: boolean;
}

export type NextFunction = (err?: unknown) => void;

async function readRawBody(req: MinimalRequest): Promise<string | undefined> {
  if (typeof req.body === 'string') return req.body;
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return JSON.stringify(req.body);
  if (Buffer.isBuffer(req.body)) return req.body.toString('utf8');
  const it = req as unknown as AsyncIterable<Buffer | string>;
  if (typeof it[Symbol.asyncIterator] !== 'function') return undefined;
  const chunks: Buffer[] = [];
  for await (const c of it) chunks.push(typeof c === 'string' ? Buffer.from(c) : c);
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Express / Connect middleware that proxies OpenAI Chat Completions, OpenAI
 * Responses and Anthropic Messages calls upstream with PII masked, restoring
 * JSON and streaming (SSE) responses. Works with or without `express.json()`.
 */
export function createExpressMiddleware(
  vela: Vela,
  opts: ExpressMiddlewareOptions = {},
): (req: MinimalRequest, res: MinimalResponse, next: NextFunction) => Promise<void> {
  const upstream = (opts.upstream ?? DEFAULT_UPSTREAM_URL).replace(/\/+$/, '');
  const upstreamFor = (path: string): string =>
    !opts.upstream && detectApiFormat(path) === 'anthropic-messages' ? DEFAULT_ANTHROPIC_URL : upstream;

  return async function velaMiddleware(req, res, next): Promise<void> {
    if ((req.method ?? 'POST').toUpperCase() !== 'POST' || !detectApiFormat(req.path)) return next();

    try {
      const body = await readRawBody(req);
      if (!body) return next();
      const controller = new AbortController();
      res.on?.('close', () => {
        if (!res.writableEnded) controller.abort();
      });
      const response = await forwardLlmRequest(
        vela,
        {
          url: upstreamFor(req.path) + (req.url ?? req.path),
          method: 'POST',
          headers: nodeHeadersToWeb(req.headers),
          body,
          signal: controller.signal,
        },
        opts.apiKey ? { apiKey: opts.apiKey } : {},
      );
      if (res.writeHead) {
        await pipeResponseToNode(response, res as Required<Pick<MinimalResponse, 'writeHead'>> & MinimalResponse);
        return;
      }
      res.status(response.status);
      response.headers.forEach((v, k) => res.setHeader(k, v));
      if (response.body) {
        const reader = response.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(Buffer.from(value));
        }
      }
      res.end();
    } catch (err) {
      if (res.headersSent) {
        res.end();
        return;
      }
      const message = err instanceof Error ? err.message : 'Unknown gateway error';
      res.status(502).json({ error: { message: `Vela privacy gateway failed to process request: ${message}`, type: 'vela_gateway_error' } });
    }
  };
}
