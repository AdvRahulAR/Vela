import type { Vela } from '../core/vela.js';
import { forwardLlmRequest } from './gateway.js';
import { detectApiFormat } from './formats.js';
import type { FetchInterceptorOptions } from '../types.js';

const KNOWN_PROVIDERS: Record<string, string[]> = {
  openai: ['api.openai.com'],
  anthropic: ['api.anthropic.com'],
  groq: ['api.groq.com'],
  together: ['api.together.xyz', 'api.together.ai'],
  ollama: ['localhost:11434', '127.0.0.1:11434'],
};

/**
 * Create a fetch() replacement that masks OpenAI (Chat Completions + Responses)
 * and Anthropic Messages calls and restores their JSON / SSE responses.
 *
 *   globalThis.fetch = createFetchInterceptor(vela);
 */
export function createFetchInterceptor(vela: Vela, opts: FetchInterceptorOptions = {}): typeof fetch {
  const originalFetch = globalThis.fetch.bind(globalThis);
  const hosts = new Set<string>();
  for (const p of opts.providers ?? []) {
    for (const h of KNOWN_PROVIDERS[p.toLowerCase()] ?? [p.toLowerCase()]) hosts.add(h);
  }

  const isTarget = (url: URL): boolean => {
    if (hosts.size > 0 && !hosts.has(url.host.toLowerCase()) && !hosts.has(url.hostname.toLowerCase())) return false;
    if (opts.targetUrls) return opts.targetUrls.some((p) => url.pathname.endsWith(p) || url.href.includes(p));
    return detectApiFormat(url.pathname) !== null;
  };

  return async function velaFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const isRequest = typeof Request !== 'undefined' && input instanceof Request;
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
    let url: URL;
    try {
      url = new URL(href);
    } catch {
      return originalFetch(input, init);
    }
    const method = (init?.method ?? (isRequest ? (input as Request).method : 'GET')).toUpperCase();
    if (method !== 'POST' || !isTarget(url) || detectApiFormat(url.pathname) === null) return originalFetch(input, init);

    let body: string | undefined;
    if (typeof init?.body === 'string') body = init.body;
    else if (init?.body instanceof Uint8Array) body = new TextDecoder().decode(init.body);
    else if (init?.body === undefined && isRequest) body = await (input as Request).clone().text();
    if (!body) return originalFetch(input, init);
    try {
      JSON.parse(body);
    } catch {
      return originalFetch(input, init);
    }

    const headers = new Headers(isRequest ? (input as Request).headers : undefined);
    new Headers(init?.headers).forEach((v, k) => headers.set(k, v));
    const sessionId = opts.sessionId?.(href, init);
    const signal = init?.signal ?? (isRequest ? (input as Request).signal : undefined);

    return forwardLlmRequest(
      vela,
      { url: href, method, headers, body, ...(signal ? { signal } : {}) },
      { fetchImpl: originalFetch, ...(sessionId ? { sessionId } : {}) },
    );
  };
}
