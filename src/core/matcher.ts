import type { EntityType, MaskResult, Replacement } from '../types.js';

/**
 * Types whose masked values are matched tolerantly on the way back: the LLM may
 * drop or change separators ("7973 0941 5855" → "797309415855") or change case.
 */
const FUZZY_TYPES: ReadonlySet<EntityType> = new Set([
  'AADHAAR',
  'CREDIT_CARD',
  'PHONE',
  'IBAN',
  'BANK_ACCOUNT',
  'SSN',
  'PAN',
  'GSTIN',
  'PASSPORT',
  'IFSC',
]);

const TOKEN_RE = /^\[([A-Z][A-Z0-9_]*_\d+)\]$/;

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function ciChar(c: string): string {
  const lo = c.toLowerCase();
  const up = c.toUpperCase();
  return lo !== up ? `[${lo}${up}]` : escapeRe(c);
}

type Kind = 'token' | 'fuzzy' | 'exact';

interface Target {
  rep: Replacement;
  kind: Kind;
  /** Normalised comparison key used for prefix (hold-back) checks. */
  core: string;
  plusPrefix: boolean;
  /** Tolerant pattern (tokens/fuzzy) — tried after every exact pattern. */
  source: string;
  /** Exact pattern. */
  exact: string;
}

function buildTarget(rep: Replacement): Target {
  const tok = TOKEN_RE.exec(rep.masked);
  if (rep.method === 'token' && tok) {
    const inner = tok[1] as string;
    const body = Array.from(inner).map(ciChar).join('');
    return {
      rep,
      kind: 'token',
      core: inner.toUpperCase(),
      plusPrefix: false,
      source: `(?:\\[\\s*)?(?<![A-Za-z0-9_])${body}(?![A-Za-z0-9_])(?:\\s*\\])?`,
      exact: escapeRe(rep.masked),
    };
  }
  const core = rep.masked.replace(/[^A-Za-z0-9]/g, '');
  if (rep.method === 'fpe' && FUZZY_TYPES.has(rep.type) && core.length >= 6) {
    const plus = rep.masked.trimStart().startsWith('+');
    const body = Array.from(core).map(ciChar).join('[\\s\\-.()/]{0,2}');
    // Exact form first, then a tolerant form (separators/case changed by the LLM).
    return {
      rep,
      kind: 'fuzzy',
      core: core.toUpperCase(),
      plusPrefix: plus,
      source: `(?<![A-Za-z0-9+(])${plus ? '\\+?' : ''}\\(?${body}(?![A-Za-z0-9])`,
      exact: `(?<![A-Za-z0-9+(])${escapeRe(rep.masked)}(?![A-Za-z0-9])`,
    };
  }
  return {
    rep,
    kind: 'exact',
    core: rep.masked,
    plusPrefix: false,
    source: '',
    exact: `(?<![A-Za-z0-9])${escapeRe(rep.masked)}(?![A-Za-z0-9]|\\.\\d)`,
  };
}

/** Collect replacement records from one or more legacy/new MaskResults. */
export function replacementsFrom(results: MaskResult | MaskResult[]): Replacement[] {
  const list = Array.isArray(results) ? results : [results];
  const seen = new Map<string, Replacement>();
  for (const r of list) {
    if (r.replacements) {
      for (const rep of r.replacements) seen.set(rep.masked, rep);
      continue;
    }
    for (const [token, original] of Object.entries(r.mapping ?? {})) {
      const t = /^\[([A-Z_]+?)_\d+\]$/.exec(token)?.[1] ?? 'CUSTOM';
      seen.set(token, { masked: token, original, type: t, method: 'token' });
    }
    for (const [original, cipher] of Object.entries(r.fpeMap ?? {})) {
      const type = r.entities?.find((e) => e.value === original)?.type ?? 'CUSTOM';
      seen.set(cipher, { masked: cipher, original, type, method: 'fpe' });
    }
  }
  return [...seen.values()];
}

export interface RestoreOptions {
  /** The text is (part of) a JSON-encoded string: escape restored values. */
  json?: boolean;
}

/**
 * Restores original values in LLM output. Shared by one-shot and streaming paths.
 */
export class Restorer {
  private readonly targets: Target[];
  /** Regex group i+1 → target. Exact patterns come first so they win over tolerant ones. */
  private readonly groups: Target[];
  private readonly re: RegExp | null;
  private readonly window: number;

  constructor(replacements: Replacement[]) {
    this.targets = replacements
      .filter((r) => r.masked.length > 0)
      .sort((a, b) => b.masked.length - a.masked.length)
      .map(buildTarget);
    const branches: Array<[Target, string]> = [
      ...this.targets.map((t): [Target, string] => [t, t.exact]),
      ...this.targets.filter((t) => t.source).map((t): [Target, string] => [t, t.source]),
    ];
    this.groups = branches.map(([t]) => t);
    this.re = branches.length ? new RegExp(branches.map(([, src]) => `(${src})`).join('|'), 'g') : null;
    this.window = this.targets.reduce((m, t) => Math.max(m, t.rep.masked.length * 2 + 4), 0);
  }

  get size(): number {
    return this.targets.length;
  }

  restore(text: string, opts: RestoreOptions = {}): { text: string; restored: number } {
    const r = this.process(text, true, opts);
    return { text: r.out, restored: r.count };
  }

  createStream(opts: RestoreOptions = {}): StreamRestorer {
    return new StreamRestorer(this, opts);
  }

  /** @internal */
  process(buf: string, final: boolean, opts: RestoreOptions): { out: string; rest: string; count: number } {
    if (!this.re || !buf) return { out: final ? buf : buf, rest: '', count: 0 };
    const re = this.re;
    re.lastIndex = 0;
    let out = '';
    let pos = 0;
    let count = 0;
    let holdFrom: number | null = null;
    let m: RegExpExecArray | null;
    while ((m = re.exec(buf)) !== null) {
      if (!final && m.index + m[0].length >= buf.length) {
        holdFrom = m.index;
        break;
      }
      let idx = 1;
      while (idx < m.length && m[idx] === undefined) idx++;
      const target = this.groups[idx - 1];
      if (!target) continue;
      const original = target.rep.original;
      out += buf.slice(pos, m.index) + (opts.json ? JSON.stringify(original).slice(1, -1) : original);
      pos = m.index + m[0].length;
      count++;
    }
    if (final) return { out: out + buf.slice(pos), rest: '', count };
    const hold = holdFrom ?? this.holdStart(buf, pos);
    return { out: out + buf.slice(pos, hold), rest: buf.slice(hold), count };
  }

  /** Earliest index ≥ from at which the buffer tail could still become a match. */
  private holdStart(buf: string, from: number): number {
    const start = Math.max(from, buf.length - this.window);
    for (let i = start; i < buf.length; i++) {
      const ch = buf[i] as string;
      if (!/[A-Za-z0-9[+(]/.test(ch)) continue;
      const prev = buf[i - 1] ?? '';
      if (/[A-Za-z0-9]/.test(prev) && ch !== '[') continue;
      const tail = buf.slice(i);
      if (this.targets.some((t) => couldStart(t, tail))) return i;
    }
    return buf.length;
  }
}

function couldStart(t: Target, tail: string): boolean {
  switch (t.kind) {
    case 'token': {
      if (!/^\[?\s*[A-Za-z0-9_]*$/.test(tail)) return false;
      const r = tail.replace(/^\[?\s*/, '').toUpperCase();
      return t.core.startsWith(r);
    }
    case 'fuzzy': {
      if (!/^\+?\(?[A-Za-z0-9\s\-.()/]*$/.test(tail)) return false;
      if (tail.startsWith('+') && !t.plusPrefix) return false;
      const r = tail.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
      return t.core.startsWith(r);
    }
    default:
      return t.core.startsWith(tail);
  }
}

/** Incremental restorer for streamed text: holds back only what could still be a masked value. */
export class StreamRestorer {
  private buffer = '';
  restored = 0;

  constructor(
    private readonly restorer: Restorer,
    private readonly opts: RestoreOptions = {},
  ) {}

  feed(chunk: string): string {
    if (!chunk) return '';
    this.buffer += chunk;
    const r = this.restorer.process(this.buffer, false, this.opts);
    this.buffer = r.rest;
    this.restored += r.count;
    return r.out;
  }

  flush(): string {
    const r = this.restorer.process(this.buffer, true, this.opts);
    this.buffer = '';
    this.restored += r.count;
    return r.out;
  }

  get pending(): boolean {
    return this.buffer.length > 0;
  }
}
