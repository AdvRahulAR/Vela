import type { Vela } from '../core/vela.js';
import { LLM_REQUEST_PATHS } from '../config/constants.js';
import { maskOpenAiRequest, unmaskOpenAiResponse } from './openai.js';
import { createSseDeMasker } from '../core/streaming.js';
import type { FetchInterceptorOptions, OpenAIRequest, OpenAIResponse } from '../types.js';

const KNOWN_PROVIDERS: Record<string, string[]> = {
  openai: ['api.openai.com'],
  anthropic: ['api.anthropic.com'],
  groq: ['api.groq.com'],
  together: ['api.together.xyz', 'api.together.ai'],
  ollama: ['localhost:11434', '127.0.0.1:11434'],
};

/**
 * Drop-in fetch interceptor.
 * Wraps globalThis.fetch to automatically mask outbound LLM requests
 * and de-mask both JSON and SSE streaming responses.
 */
export function createFetchInterceptor(
  vela: Vela,
  opts: FetchInterceptorOptions = {}
): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  const originalFetch = globalThis.fetch.bind(globalThis);
  const targetPaths = opts.targetUrls ?? LLM_REQUEST_PATHS;

  // Build list of domains to match if providers specified
  const providerDomains: string[] = [];
  if (opts.providers && opts.providers.length > 0) {
    for (const provider of opts.providers) {
      const lower = provider.toLowerCase();
      const domains = KNOWN_PROVIDERS[lower];
      if (domains) {
        providerDomains.push(...domains);
      } else {
        providerDomains.push(lower);
      }
    }
  }

  return async function velaFetch(
    input: RequestInfo | URL,
    init?: RequestInit
  ): Promise<Response> {
    const url =
      typeof input === 'string'
        ? input
        : input instanceof URL
        ? input.href
        : input.url;

    const matchesPath = targetPaths.some((p) => url.includes(p));
    const matchesProvider =
      providerDomains.length > 0
        ? providerDomains.some((d) => url.includes(d))
        : true;

    const isTarget = matchesPath && matchesProvider;
    if (!isTarget || !init?.body || typeof init.body !== 'string') {
      return originalFetch(input, init);
    }

    let body: OpenAIRequest;
    try {
      body = JSON.parse(init.body) as OpenAIRequest;
    } catch {
      return originalFetch(input, init);
    }

    const { payload, results } = maskOpenAiRequest(vela, body);
    const maskedInit: RequestInit = {
      ...init,
      body: JSON.stringify(payload),
    };

    const response = await originalFetch(input, maskedInit);
    const contentType = response.headers.get('content-type') || '';

    // Handle Server-Sent Events (SSE streaming)
    if (contentType.includes('text/event-stream') && response.body) {
      const deMasker = createSseDeMasker(results);
      const decoder = new TextDecoder();
      const encoder = new TextEncoder();

      const transformStream = new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          const text = decoder.decode(chunk, { stream: true });
          const processed = deMasker(text);
          if (processed) {
            controller.enqueue(encoder.encode(processed));
          }
        },
      });

      const stream = response.body.pipeThrough(transformStream);
      return new Response(stream, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    }

    // Handle standard JSON completions
    if (contentType.includes('application/json')) {
      const clone = response.clone();
      const json = (await clone.json()) as OpenAIResponse;
      const unmasked = unmaskOpenAiResponse(vela, json, results);

      return new Response(JSON.stringify(unmasked), {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    }

    return response;
  };
}
