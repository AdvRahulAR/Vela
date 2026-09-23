import type { Vela } from '../core/vela.js';
import { DEFAULT_UPSTREAM_URL, LLM_REQUEST_PATHS } from '../config/constants.js';
import { maskOpenAiRequest, unmaskOpenAiResponse } from './openai.js';
import { createSseDeMasker } from '../core/streaming.js';
import type { ExpressMiddlewareOptions, OpenAIRequest, OpenAIResponse } from '../types.js';

export interface MinimalRequest {
  path: string;
  method?: string;
  body?: unknown;
  headers: Record<string, string | string[] | undefined>;
}

export interface MinimalResponse {
  status: (code: number) => MinimalResponse;
  json: (body: unknown) => void;
  setHeader: (name: string, value: string) => void;
  write: (chunk: unknown) => boolean;
  end: () => void;
}

export type NextFunction = (err?: unknown) => void;

/**
 * Express / Connect middleware for LLM proxy routes.
 * Intercepts incoming completion requests, masks PII before forwarding
 * upstream, and restores responses before sending to client.
 */
export function createExpressMiddleware(
  vela: Vela,
  opts: ExpressMiddlewareOptions = {}
): (req: MinimalRequest, res: MinimalResponse, next: NextFunction) => Promise<void> {
  const upstream = opts.upstream ?? DEFAULT_UPSTREAM_URL;

  return async function velaMiddleware(
    req: MinimalRequest,
    res: MinimalResponse,
    next: NextFunction
  ): Promise<void> {
    const isTarget = LLM_REQUEST_PATHS.some((p) => req.path === p || req.path.endsWith(p));
    if (!isTarget || !req.body || typeof req.body !== 'object') {
      return next();
    }

    try {
      const { payload, results } = maskOpenAiRequest(vela, req.body as OpenAIRequest);
      const url = upstream.replace(/\/+$/, '') + req.path;

      const headers: Record<string, string> = {
        'content-type': 'application/json',
      };

      if (opts.apiKey) {
        headers['authorization'] = `Bearer ${opts.apiKey}`;
      } else if (typeof req.headers['authorization'] === 'string') {
        headers['authorization'] = req.headers['authorization'];
      }

      const upstreamRes = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      });

      const contentType = upstreamRes.headers.get('content-type') || '';

      // Streaming Server-Sent Events response
      if (contentType.includes('text/event-stream') && upstreamRes.body) {
        res.status(upstreamRes.status);
        res.setHeader('content-type', 'text/event-stream');
        res.setHeader('cache-control', 'no-cache');
        res.setHeader('connection', 'keep-alive');

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
        return;
      }

      if (contentType.includes('application/json')) {
        const json = (await upstreamRes.json()) as OpenAIResponse;
        const unmasked = unmaskOpenAiResponse(vela, json, results);
        res.status(upstreamRes.status).json(unmasked);
        return;
      }

      // Pass-through for other status codes or error bodies
      const text = await upstreamRes.text();
      res.status(upstreamRes.status).json({ message: text });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown gateway error';
      res.status(502).json({
        error: {
          message: `Vela privacy gateway failed to process request: ${message}`,
          type: 'vela_gateway_error',
        },
      });
    }
  };
}
