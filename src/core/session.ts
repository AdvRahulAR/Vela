import { randomBytes } from 'node:crypto';
import { detectPii, nameComponents, type DetectOptions } from './detector.js';
import type { FpeMasker } from './fpe.js';
import { Restorer, type RestoreOptions, type StreamRestorer } from './matcher.js';
import type { DetectedEntity, EntityType, MaskResult, Replacement, SessionOptions } from '../types.js';

/** JSON keys whose string values are themselves JSON documents (tool-call arguments). */
const JSON_STRING_KEYS = new Set(['arguments', 'partial_json']);

/** @internal Shared engine state handed to sessions by Vela. */
export interface SessionEngine {
  fpe: FpeMasker;
  fpeTypes: EntityType[];
  tokenTypes: EntityType[];
  detect: Omit<DetectOptions, 'knownNames' | 'prefix'>;
}

function humanizeKey(key: string): string {
  return key.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_\-.]+/g, ' ').trim();
}

/**
 * A masking session: one request, one conversation turn or one whole
 * conversation. Every value masked through the same session gets one unique,
 * consistent placeholder, so multi-message requests restore correctly.
 */
export class MaskSession {
  readonly sessionId: string | undefined;
  private readonly seed: string;
  private readonly counters = new Map<string, number>();
  private readonly byOriginal = new Map<string, Replacement>();
  private readonly byMasked = new Map<string, Replacement>();
  private readonly knownNames = new Set<string>();
  private readonly allEntities: DetectedEntity[] = [];
  private restorer: Restorer | null = null;

  constructor(
    private readonly engine: SessionEngine,
    opts: SessionOptions = {},
  ) {
    this.sessionId = opts.sessionId;
    this.seed = opts.sessionId !== undefined ? `sid:${opts.sessionId}` : `rnd:${randomBytes(16).toString('hex')}`;
  }

  /** All replacements made so far in this session. */
  get replacements(): Replacement[] {
    return [...this.byMasked.values()];
  }

  get entities(): DetectedEntity[] {
    return [...this.allEntities];
  }

  /**
   * Pre-scan texts so that names first seen in a later message are also masked
   * where they are re-mentioned in earlier messages.
   */
  learn(text: string, prefix?: string): void {
    if (!text || this.engine.detect.detectNames === false) return;
    const ents = detectPii(text, { ...this.engine.detect, knownNames: this.knownNames, ...(prefix ? { prefix } : {}) });
    for (const n of nameComponents(ents)) this.knownNames.add(n);
  }

  /** Mask one string. */
  mask(text: string, prefix?: string): string {
    if (!text) return text;
    const entities = detectPii(text, {
      ...this.engine.detect,
      knownNames: this.knownNames,
      ...(prefix ? { prefix } : {}),
    });
    for (const n of nameComponents(entities)) this.knownNames.add(n);

    let out = '';
    let pos = 0;
    for (const e of entities) {
      const masked = this.maskEntity(e, text);
      if (masked === null) continue;
      out += text.slice(pos, e.start) + masked;
      pos = e.end;
      this.allEntities.push(e);
    }
    return out + text.slice(pos);
  }

  /** Mask a string that may contain JSON (e.g. tool-call arguments). */
  maskJsonString(s: string): string {
    const parsed = tryParseJson(s);
    if (parsed !== undefined && typeof parsed === 'object' && parsed !== null) {
      return JSON.stringify(this.maskValue(parsed));
    }
    return this.mask(s);
  }

  /** Deep-mask every string leaf of a JSON-like value; object keys provide context cues. */
  maskValue<T>(value: T, key?: string): T {
    if (typeof value === 'string') {
      return this.mask(value, key ? `${humanizeKey(key)}: ` : undefined) as unknown as T;
    }
    if (Array.isArray(value)) return value.map((v) => this.maskValue(v, key)) as unknown as T;
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) out[k] = this.maskValue(v, k);
      return out as T;
    }
    return value;
  }

  /** Learning pass over a JSON-like value (see learn()). */
  learnValue(value: unknown, key?: string): void {
    if (typeof value === 'string') {
      const parsed = JSON_STRING_KEYS.has(key ?? '') ? tryParseJson(value) : undefined;
      if (parsed && typeof parsed === 'object') this.learnValue(parsed);
      else this.learn(value, key ? `${humanizeKey(key)}: ` : undefined);
    } else if (Array.isArray(value)) value.forEach((v) => this.learnValue(v, key));
    else if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) this.learnValue(v, k);
    }
  }

  /** Restore originals in a complete text. */
  unmask(text: string, opts?: RestoreOptions): { text: string; restored: number } {
    return this.getRestorer().restore(text, opts);
  }

  /** Restore originals in every string of a JSON-like value (JSON-string fields are escaped correctly). */
  unmaskValue<T>(value: T, key?: string): T {
    if (typeof value === 'string') {
      return this.getRestorer().restore(value, { json: JSON_STRING_KEYS.has(key ?? '') }).text as unknown as T;
    }
    if (Array.isArray(value)) return value.map((v) => this.unmaskValue(v, key)) as unknown as T;
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) out[k] = this.unmaskValue(v, k);
      return out as T;
    }
    return value;
  }

  createStreamDeMasker(opts?: RestoreOptions): StreamRestorer {
    return this.getRestorer().createStream(opts);
  }

  /** Snapshot as a (backwards-compatible) MaskResult. */
  toResult(text = ''): MaskResult {
    const mapping: Record<string, string> = {};
    const fpeMap: Record<string, string> = {};
    for (const r of this.byMasked.values()) {
      if (r.method === 'token') mapping[r.masked] = r.original;
      else fpeMap[r.original] = r.masked;
    }
    return { text, mapping, fpeMap, entities: this.entities, replacements: this.replacements };
  }

  private getRestorer(): Restorer {
    if (!this.restorer || this.restorer.size !== this.byMasked.size) {
      this.restorer = new Restorer(this.replacements);
    }
    return this.restorer;
  }

  /** Returns the masked form, or null if this entity type is not configured for masking. */
  private maskEntity(e: DetectedEntity, text: string): string | null {
    const key = `${e.type}\u0000${e.value}`;
    const existing = this.byOriginal.get(key);
    if (existing) return existing.masked;

    const wantsFpe = this.engine.fpeTypes.includes(e.type);
    const wantsToken = this.engine.tokenTypes.includes(e.type);
    if (!wantsFpe && !wantsToken) return null;

    let rep: Replacement | null = null;
    if (wantsFpe) {
      const c = this.engine.fpe.encryptEntity(e.type, e.value, this.seed, e.metadata);
      if (c && c !== e.value && !this.byMasked.has(c) && !text.includes(c)) {
        rep = { masked: c, original: e.value, type: e.type, method: 'fpe' };
      }
    }
    // Fail closed: anything that could not be format-preserved becomes a token.
    if (!rep) rep = { masked: this.nextToken(e.type, text), original: e.value, type: e.type, method: 'token' };

    this.byOriginal.set(key, rep);
    this.byMasked.set(rep.masked, rep);
    return rep.masked;
  }

  private nextToken(type: EntityType, text: string): string {
    const base = String(type).toUpperCase().replace(/[^A-Z0-9_]/g, '_') || 'PII';
    let n = this.counters.get(base) ?? 0;
    let token: string;
    do {
      n++;
      token = `[${base}_${n}]`;
    } while (this.byMasked.has(token) || text.includes(token));
    this.counters.set(base, n);
    return token;
  }
}

function tryParseJson(s: string): unknown {
  const t = s.trim();
  if (!(t.startsWith('{') || t.startsWith('['))) return undefined;
  try {
    return JSON.parse(t);
  } catch {
    return undefined;
  }
}
