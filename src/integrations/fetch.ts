import type { Vela } from '../core/vela.js';
import { VelaError, VelaRouteBlockedError } from '../core/errors.js';
import { auditBlocked, forwardFieldsRequest, forwardLlmRequest } from './gateway.js';
import { classifyRoute } from './formats.js';
import type { FetchInterceptorOptions } from '../types.js';

const KNOWN_PROVIDERS: Record<string, string[]> = {
  openai: ['api.openai.com'],
  anthropic: ['api.anthropic.com'],
  groq: ['api.groq.com'],
  together: ['api.together.xyz', 'api.together.ai'],
  ollama: ['localhost:11434', '127.0.0.1:11434'],
};

/**
 * Hosted LLM APIs. On these hosts every route is classified: maskable routes
 * are masked, body-free ones pass, and anything else is blocked (fail closed).
 */
const PROVIDER_HOSTS = new Set(['api.openai.com', 'api.anthropic.com', 'api.groq.com', 'api.together.xyz', 'api.together.ai']);
const PROVIDER_SUFFIXES = ['.openai.azure.com', '.services.ai.azure.com', '.cognitiveservices.azure.com'];
/** Lower-cased hostname without a trailing dot (`api.openai.com.` is the same host). */
const normHost = (h: string): string => h.toLowerCase().replace(/\.$/, '');

/**
 * Create a fetch() replacement that masks OpenAI (Chat Completions + Responses)
 * and Anthropic Messages calls and restores their JSON / SSE responses.
 *
 *   globalThis.fetch = createFetchInterceptor(vela);
 *
 * On a known provider host, routes Vela can't mask (batches, files, unknown
 * endpoints) throw `VelaRouteBlockedError` unless `passthrough: 'all'` is set.
 * A request to a maskable route whose body can't be read as JSON throws
 * instead of being sent as-is.
 */
export function createFetchInterceptor(vela: Vela, opts: FetchInterceptorOptions = {}): typeof fetch {
  const originalFetch = globalThis.fetch.bind(globalThis);
  const hosts = new Set<string>();
  for (const p of opts.providers ?? []) {
    for (const h of KNOWN_PROVIDERS[p.toLowerCase()] ?? [p.toLowerCase()]) hosts.add(h);
  }

  const hostMatches = (url: URL): boolean =>
    hosts.size === 0 || hosts.has(normHost(url.host)) || hosts.has(normHost(url.hostname));
  // Hosts the caller listed in `providers` get the same fail-closed route rules as the built-in ones.
  const isProviderHost = (url: URL): boolean => {
    const h = normHost(url.hostname);
    return PROVIDER_HOSTS.has(h) || PROVIDER_SUFFIXES.some((s) => h.endsWith(s)) || hosts.has(h) || hosts.has(normHost(url.host));
  };
  const targetMatches = (url: URL): boolean =>
    !opts.targetUrls || opts.targetUrls.some((p) => url.pathname.endsWith(p) || url.href.includes(p));

  return async function velaFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const isRequest = typeof Request !== 'undefined' && input instanceof Request;
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
    let url: URL;
    try {
      url = new URL(href);
    } catch {
      return originalFetch(input, init);
    }
    if (!hostMatches(url) || !targetMatches(url)) return originalFetch(input, init);

    const method = (init?.method ?? (isRequest ? (input as Request).method : 'GET')).toUpperCase();
    const provider = isProviderHost(url);
    const route = classifyRoute(method, url.pathname);
    // Off provider hosts only the well-known LLM paths are masked; other traffic is the app's own.
    const maskable = route.kind === 'llm' || (provider && route.kind === 'fields');
    if (!maskable) {
      if (provider && route.kind === 'blocked' && opts.passthrough !== 'all') {
        const err = new VelaRouteBlockedError(method, url.pathname, route.reason);
        auditBlocked(vela, method, url.origin + url.pathname, err);
        throw err;
      }
      // Body-free methods on a provider host: drop any body so nothing rides along unmasked.
      if (provider && route.kind === 'safe' && (init?.body != null || (isRequest && (input as Request).body !== null))) {
        const headers = new Headers(isRequest ? (input as Request).headers : undefined);
        new Headers(init?.headers).forEach((v, k) => headers.set(k, v));
        headers.delete('content-length');
        const signal = init?.signal ?? (isRequest ? (input as Request).signal : undefined);
        return originalFetch(href, { method, headers, ...(signal ? { signal } : {}) });
      }
      return originalFetch(input, init);
    }

    let body: string | undefined;
    try {
      if (init?.body !== undefined && init.body !== null) {
        body = typeof init.body === 'string' ? init.body : await new Request(href, { method, body: init.body, duplex: 'half' } as RequestInit).text();
      } else if (isRequest) {
        body = await (input as Request).clone().text();
      }
    } catch (err) {
      throw new VelaError(`Vela could not read the request body; nothing was sent (${err instanceof Error ? err.message : String(err)})`, 400);
    }
    if (!body) return originalFetch(input, init);
    try {
      JSON.parse(body);
    } catch {
      throw new VelaError('Request body to an LLM route is not valid JSON; Vela did not send it', 400);
    }

    const headers = new Headers(isRequest ? (input as Request).headers : undefined);
    new Headers(init?.headers).forEach((v, k) => headers.set(k, v));
    const sessionId = opts.sessionId?.(href, init);
    const signal = init?.signal ?? (isRequest ? (input as Request).signal : undefined);
    const req = { url: href, method, headers, body, ...(signal ? { signal } : {}) };
    const fwd = { fetchImpl: originalFetch, ...(sessionId ? { sessionId } : {}) };

    return route.kind === 'fields' ? forwardFieldsRequest(vela, req, route.fields, fwd) : forwardLlmRequest(vela, req, fwd);
  };
}

