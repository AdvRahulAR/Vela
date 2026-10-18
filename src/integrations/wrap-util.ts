import type { Vela } from '../core/vela.js';
import { VelaError, VelaRouteBlockedError } from '../core/errors.js';
import { maskFieldsAsync } from './formats.js';
import { enforceRequestPolicy } from './gateway.js';

type Fn = (...args: any[]) => any; // eslint-disable-line @typescript-eslint/no-explicit-any
type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** Read-only and control methods that send no text: allowed through the wrapper untouched. */
const SAFE_METHOD = /^(list|retrieve|get|del|delete|cancel|content|retrieveContent|results|poll|waitForProcessing|constructor|toString|toJSON|valueOf)$/;

/**
 * Wrap an SDK client in an allowlist. Methods in `overrides` (by dotted path,
 * e.g. `chat.completions.create`) are replaced; read-only methods (`list`,
 * `retrieve`, `del`, `cancel`…) pass; **every other method throws
 * `VelaRouteBlockedError`**, so a method Vela doesn't know (a new SDK helper,
 * legacy completions, raw `client.post`) can't send unmasked text.
 */
export function guardClient<T extends object>(client: T, overrides: Record<string, (original: Fn) => Fn>, reasons: Record<string, string> = {}): T {
  const cache = new Map<string, unknown>();
  const wrap = (target: object, path: string[]): unknown => {
    const key = path.join('.');
    const hit = cache.get(key);
    if (hit) return hit;
    const proxy = new Proxy(target, {
      get(t, prop) {
        const v: unknown = Reflect.get(t, prop, t);
        if (typeof prop === 'symbol') return typeof v === 'function' ? v.bind(t) : v;
        const p = [...path, prop];
        const name = p.join('.');
        if (typeof v === 'function') {
          const override = overrides[name];
          if (override) return override((v as Fn).bind(t));
          if (SAFE_METHOD.test(prop)) return (v as Fn).bind(t);
          return () => {
            throw new VelaRouteBlockedError('SDK', name, reasons[name] ?? 'Vela does not mask this method');
          };
        }
        if (v && typeof v === 'object') return wrap(v, p);
        return v;
      },
    });
    cache.set(key, proxy);
    return proxy;
  };
  return wrap(client, []) as T;
}

/** The client's base URL (OpenAI and Anthropic SDKs expose `baseURL`), for the providers allowlist. */
export function baseUrlOf(client: unknown): string | undefined {
  const u = (client as { baseURL?: unknown } | null)?.baseURL;
  return typeof u === 'string' ? u : undefined;
}

/** A method whose top-level text fields (`input`, `prompt`) are masked and whose result is restored. */
export function fieldsMethod(vela: Vela, fields: string[], sessionId: (p: Json) => string | undefined, baseUrl?: string) {
  return (original: Fn): Fn =>
    async (params: Json, ...rest: unknown[]) => {
      enforceRequestPolicy(vela, baseUrl, params ?? {});
      if (params?.stream === true) throw new VelaError('Streaming is not supported for this method through Vela; nothing was sent', 400);
      const sid = sessionId(params);
      const session = vela.createSession(sid !== undefined ? { sessionId: sid } : {});
      const payload = await maskFieldsAsync(session, fields, params);
      return session.unmaskValue(await original(payload, ...rest));
    };
}
