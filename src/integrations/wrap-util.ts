import type { Vela } from '../core/vela.js';
import { VelaError, VelaRouteBlockedError } from '../core/errors.js';
import { maskFieldsAsync } from './formats.js';
import { AuditTrail, enforceRequestPolicy } from './gateway.js';
import type { MaskSession } from '../core/session.js';

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
  // `internal`: under a `_`-prefixed property (the SDK's own HTTP client). Nothing there is safe.
  const wrap = (target: object, path: string[], internal: boolean): unknown => {
    const key = path.join('.');
    const hit = cache.get(key);
    if (hit) return hit;
    const proxy = new Proxy(target, {
      get(t, prop) {
        const v: unknown = Reflect.get(t, prop, t);
        if (typeof prop === 'symbol') return typeof v === 'function' ? v.bind(t) : v;
        const p = [...path, prop];
        const name = p.join('.');
        const isInternal = internal || prop.startsWith('_');
        if (typeof v === 'function') {
          const override = overrides[name];
          if (override) return override((v as Fn).bind(t));
          // Read-only names are safe only on a resource (`models.list`), never on the client
          // root, where `get`/`delete` are raw HTTP helpers that take any path and body.
          if (!isInternal && path.length > 0 && SAFE_METHOD.test(prop)) return (v as Fn).bind(t);
          return () => {
            throw new VelaRouteBlockedError('SDK', name, reasons[name] ?? 'Vela does not mask this method');
          };
        }
        if (v && typeof v === 'object') return wrap(v, p, isInternal);
        return v;
      },
    });
    cache.set(key, proxy);
    return proxy;
  };
  return wrap(client, [], false) as T;
}

/** The client's base URL (OpenAI and Anthropic SDKs expose `baseURL`), for the providers allowlist. */
export function baseUrlOf(client: unknown): string | undefined {
  const u = (client as { baseURL?: unknown } | null)?.baseURL;
  return typeof u === 'string' ? u : undefined;
}

interface AuditedMethodOptions {
  vela: Vela;
  client: unknown;
  /** Provider path for this method (e.g. `/chat/completions`), for audit events. */
  route: string;
  format: string;
  sessionId: (params: Json) => string | undefined;
  mask: (session: MaskSession, params: Json) => Promise<Json>;
  /** Wrap a streaming result; call `done` when the stream has ended. */
  stream?: (result: object, session: MaskSession, done: () => void) => unknown;
}

/**
 * A wrapped SDK method with the same guarantees as the proxy: request policy,
 * masking, an audit event before anything is sent (fail closed), the call,
 * restoration, and a response (or error) audit event.
 */
export function auditedMethod(o: AuditedMethodOptions) {
  return (original: Fn): Fn =>
    async (params: Json, ...rest: unknown[]) => {
      const sid = o.sessionId(params);
      const base = baseUrlOf(o.client);
      const trail = new AuditTrail(o.vela, {
        method: 'POST',
        url: (base ?? 'sdk://client').replace(/\/+$/, '') + o.route,
        format: o.format,
        model: params?.model,
        stableSession: sid !== undefined,
      });
      const session = o.vela.createSession(sid !== undefined ? { sessionId: sid } : {});
      let result: unknown;
      try {
        enforceRequestPolicy(o.vela, base, params ?? {});
        const payload = await o.mask(session, params);
        await trail.request(session);
        result = await original(payload, ...rest);
      } catch (err) {
        trail.error(err);
        throw err;
      }
      const done = (): void => trail.response(session, 200);
      if (o.stream && result && typeof result === 'object' && Symbol.asyncIterator in result) return o.stream(result, session, done);
      const out = session.unmaskValue(result);
      done();
      return out;
    };
}

/** A method whose top-level text fields (`input`, `prompt`) are masked and whose result is restored. */
export function fieldsMethod(vela: Vela, client: unknown, route: string, fields: string[], sessionId: (p: Json) => string | undefined) {
  return auditedMethod({
    vela,
    client,
    route,
    format: 'fields',
    sessionId,
    mask: async (session, params) => {
      if (params?.stream === true) throw new VelaError('Streaming is not supported for this method through Vela; nothing was sent', 400);
      return maskFieldsAsync(session, fields, params);
    },
  });
}
