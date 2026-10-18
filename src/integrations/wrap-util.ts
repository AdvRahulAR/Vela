import type { Vela } from '../core/vela.js';
import { VelaError, VelaRouteBlockedError } from '../core/errors.js';
import { maskFieldsAsync } from './formats.js';

type Fn = (...args: any[]) => any; // eslint-disable-line @typescript-eslint/no-explicit-any
type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/**
 * Return a copy of `root` (built with Object.create, so everything else is
 * inherited) whose method at `path` is replaced by `make(original)`. If the
 * method doesn't exist on this client version, `root` is returned unchanged.
 */
export function overrideMethod<T extends object>(root: T, path: string[], make: (original: Fn) => Fn): T {
  const [name, ...rest] = path as [string, ...string[]];
  const current = (root as Json)[name];
  if (rest.length === 0) {
    if (typeof current !== 'function') return root;
    const out = Object.create(root);
    out[name] = make(current.bind(root));
    return out;
  }
  if (!current || (typeof current !== 'object' && typeof current !== 'function')) return root;
  const child = overrideMethod(current, rest, make);
  if (child === current) return root;
  const out = Object.create(root);
  out[name] = child;
  return out;
}

/** Replace methods Vela can't mask (batches, files, stream helpers…) with ones that throw. */
export function blockMethods<T extends object>(client: T, blocked: Array<[string, string]>): T {
  let out = client;
  for (const [path, reason] of blocked) {
    out = overrideMethod(out, path.split('.'), () => () => {
      throw new VelaRouteBlockedError('SDK', path, reason);
    });
  }
  return out;
}

/** A method whose top-level text fields (`input`, `prompt`) are masked and whose result is restored. */
export function fieldsMethod(vela: Vela, fields: string[], sessionId: (p: Json) => string | undefined) {
  return (original: Fn): Fn =>
    async (params: Json, ...rest: unknown[]) => {
      if (params?.stream === true) throw new VelaError('Streaming is not supported for this method through Vela; nothing was sent', 400);
      const sid = sessionId(params);
      const session = vela.createSession(sid !== undefined ? { sessionId: sid } : {});
      const payload = await maskFieldsAsync(session, fields, params);
      return session.unmaskValue(await original(payload, ...rest));
    };
}
