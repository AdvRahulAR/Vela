import { randomBytes } from 'node:crypto';
import { STANDARD_ENTITY_TYPES } from '../config/constants.js';
import { detectPii, nameComponents, type DetectOptions } from './detector.js';
import type { FpeMasker } from './fpe.js';
import { personComponents } from './names.js';
import { VelaInputTooLargeError, VelaNotPreparedError, VelaPolicyBlockedError, VelaRecognizerError } from './errors.js';
import { invalidateCheck } from './fpe.js';
import type { EntityAction } from './policy.js';
import { Restorer, type RestoreField, type RestoreOptions, type StreamRestorer } from './matcher.js';
import { fieldForKey } from './streaming.js';
import type {
  AsyncEntityRecognizer,
  DetectedEntity,
  EntityType,
  MaskResult,
  RecognizedSpan,
  Replacement,
  SessionOptions,
} from '../types.js';

/**
 * Opaque blobs the residual pass leaves alone: only under these keys, and only
 * when the value really is base64 or a data: URL. "ravi@example.com" under
 * `data` is not a blob and is scanned like anything else.
 */
const BLOB_KEYS = new Set(['signature', 'data', 'b64_json', 'file_data', 'encrypted_content', 'image_url', 'url']);
const BLOB_VALUE = /^(?:data:[\w/+.-]+;base64,)?[A-Za-z0-9+/=_-]{16,}$/;
const isBlob = (key: string | undefined, v: string): boolean => !!key && BLOB_KEYS.has(key) && BLOB_VALUE.test(v);

/** JSON keys whose string values are themselves JSON documents (tool-call arguments). */
const JSON_STRING_KEYS = new Set(['arguments', 'partial_json']);

/** @internal Shared engine state handed to sessions by Vela. */
export interface SessionEngine {
  fpe: FpeMasker;
  fpeTypes: EntityType[];
  tokenTypes: EntityType[];
  detect: Omit<DetectOptions, 'knownNames' | 'prefix'>;
  /** Largest single text accepted by mask()/learn(); larger input throws VelaInputTooLargeError. */
  maxInputChars: number;
  asyncRecognizers: AsyncEntityRecognizer[];
  recognizerFailure: 'block' | 'continue';
  recognizerTimeoutMs: number;
  /** Called when a recognizer fails and recognizerFailure is 'continue'. */
  onRecognizerFailure?: (err: unknown) => void;
  /** Per-field restore policy ('restore' unless set). */
  restore?: RestorePolicy;
  /** Per-type actions from a policy; they override fpeTypes/tokenTypes. */
  actions?: Record<string, EntityAction>;
  policyId?: string;
}

/** Whether placeholders in each part of a response are restored or left as placeholders. */
export interface RestorePolicy {
  /** Content text. Default 'restore'. */
  content?: 'restore' | 'placeholders';
  /**
   * Tool-call arguments. 'placeholders' stops a prompt-injected model from
   * smuggling a real value into a tool call (see THREAT_MODEL.md). Default 'restore'.
   */
  toolArguments?: 'restore' | 'placeholders';
  /** Model reasoning / thinking text. Default 'restore'. */
  thinking?: 'restore' | 'placeholders';
}

/** Placeholders found in responses, per field: restored, or kept by the restore policy. */
export interface RestoreReport {
  restored: Record<RestoreField, number>;
  kept: Record<RestoreField, number>;
}

const POLICY_KEY: Record<RestoreField, keyof RestorePolicy> = { content: 'content', tool_args: 'toolArguments', thinking: 'thinking' };

/** Strings an NER service can't find anything in: skip the round trip. */
const isTrivial = (s: string): boolean => s.length < 3 || !/[\p{L}\p{N}]/u.test(s);

function withTimeout<T>(p: Promise<T>, ms: number, controller: AbortController): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`recognizer timed out after ${ms} ms`));
    }, ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
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
  /** Placeholder-shaped strings already present in user input; never issued as real tokens. */
  private readonly reserved = new Set<string>();
  private readonly allEntities: DetectedEntity[] = [];
  /** PERSON replacements with their normalised name components, for partial-mention linking. */
  private readonly persons: Array<{ rep: Replacement; components: Set<string> }> = [];
  private readonly linkPartialNames: boolean;
  /** Spans from async recognizers, per exact text, filled by prepare(). */
  private readonly prepared = new Map<string, RecognizedSpan[]>();
  private restorer: Restorer | null = null;
  /** NER status for this session: whether async recognizers ran, and whether one failed. */
  nerStatus: 'none' | 'ok' | 'failed_continued' = 'none';
  private readonly report: RestoreReport = {
    restored: { content: 0, tool_args: 0, thinking: 0 },
    kept: { content: 0, tool_args: 0, thinking: 0 },
  };

  constructor(
    private readonly engine: SessionEngine,
    opts: SessionOptions = {},
  ) {
    this.sessionId = opts.sessionId;
    this.seed = opts.sessionId !== undefined ? `sid:${opts.sessionId}` : `rnd:${randomBytes(16).toString('hex')}`;
    this.linkPartialNames = opts.linkPartialNames ?? true;
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
    if (!text) return;
    this.checkSize(text);
    this.reserveLiteralTokens(text);
    if (this.engine.detect.detectNames === false) return;
    const ents = detectPii(text, {
      ...this.engine.detect,
      knownNames: this.knownNames,
      ...(prefix ? { prefix } : {}),
      ...this.precomputedFor(text),
    });
    for (const n of nameComponents(ents)) this.knownNames.add(n);
    // Register full names now so a partial mention in an earlier message links to them.
    this.registerFullNames(ents, text);
  }

  /** True when async recognizers are configured, so text must be prepared before masking. */
  get needsPreparation(): boolean {
    return this.engine.asyncRecognizers.length > 0;
  }

  /**
   * Run the async recognizers (NER services) over `texts` once, ahead of
   * mask()/learn(). Required when `asyncRecognizers` is configured. On failure,
   * throws VelaRecognizerError ('block', the default) or falls back to built-in
   * detection ('continue').
   */
  async prepare(texts: Iterable<string>): Promise<void> {
    if (!this.needsPreparation) return;
    const todo: string[] = [];
    for (const t of new Set(texts)) {
      if (typeof t !== 'string' || this.prepared.has(t)) continue;
      this.checkSize(t);
      if (isTrivial(t)) this.prepared.set(t, []);
      else todo.push(t);
    }
    if (todo.length === 0) return;

    const merged: RecognizedSpan[][] = todo.map(() => []);
    for (const rec of this.engine.asyncRecognizers) {
      const controller = new AbortController();
      try {
        const res = await withTimeout(rec(todo, controller.signal), this.engine.recognizerTimeoutMs, controller);
        if (!Array.isArray(res) || res.length !== todo.length) {
          throw new Error(`recognizer returned ${Array.isArray(res) ? res.length : typeof res} results for ${todo.length} texts`);
        }
        res.forEach((spans, i) => {
          const text = todo[i] as string;
          for (const s of Array.isArray(spans) ? spans : []) {
            if (Number.isInteger(s.start) && Number.isInteger(s.end) && s.start >= 0 && s.end > s.start && s.end <= text.length) {
              (merged[i] as RecognizedSpan[]).push(s);
            }
          }
        });
      } catch (err) {
        if (this.engine.recognizerFailure === 'block') throw new VelaRecognizerError(err);
        this.engine.onRecognizerFailure?.(err);
        this.nerStatus = 'failed_continued';
      }
    }
    if (this.nerStatus === 'none') this.nerStatus = 'ok';
    todo.forEach((t, i) => this.prepared.set(t, merged[i] as RecognizedSpan[]));
  }

  /**
   * prepare() every string in a JSON-like value, including the leaves of
   * strings that are themselves JSON documents (tool-call arguments). Collects a
   * superset of what maskValue()/maskLlmRequest() will mask.
   */
  async prepareValue(value: unknown): Promise<void> {
    if (!this.needsPreparation) return;
    const out: string[] = [];
    const walk = (v: unknown): void => {
      if (typeof v === 'string') {
        out.push(v);
        const parsed = tryParseJson(v);
        if (parsed && typeof parsed === 'object') walk(parsed);
      } else if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === 'object') Object.values(v).forEach(walk);
    };
    walk(value);
    await this.prepare(out);
  }

  private precomputedFor(text: string): { precomputed?: RecognizedSpan[] } {
    if (!this.needsPreparation) return {};
    const spans = this.prepared.get(text);
    if (spans === undefined) throw new VelaNotPreparedError();
    return { precomputed: spans };
  }

  /** Create replacements for multi-word person names first (longest first), so partial mentions link to them. */
  private registerFullNames(entities: DetectedEntity[], text: string): void {
    if (!this.linkPartialNames) return;
    const full = entities
      .filter((e) => e.type === 'PERSON')
      .map((e) => ({ e, n: personComponents(e.value).length }))
      .filter((x) => x.n >= 2)
      .sort((a, b) => b.n - a.n);
    for (const { e } of full) this.maskEntity(e, text);
  }

  /** Mask one string. */
  mask(text: string, prefix?: string): string {
    return this.maskText(text, prefix, false);
  }

  /**
   * Fail-closed backstop run over a request after the format-aware walk:
   * masks any detected value in string leaves the walk didn't cover (unknown
   * fields such as `user`, `metadata`, `suffix`, message `name`). Values this
   * session already masked are left alone, so nothing is masked twice.
   */
  maskResidual<T>(value: T, key?: string): T {
    if (typeof value === 'string') {
      if (isBlob(key, value)) return value;
      return this.maskText(value, key ? `${humanizeKey(key)}: ` : undefined, true) as unknown as T;
    }
    if (Array.isArray(value)) return value.map((v) => this.maskResidual(v, key)) as unknown as T;
    if (value && typeof value === 'object') {
      const o = value as Record<string, unknown>;
      // A signed thinking block must reach the provider exactly as it produced it. That is only
      // safe when the client never saw real values in it (restore.thinking: 'placeholders');
      // otherwise its text is masked like any other text and the provider may reject the signature.
      if (o.type === 'thinking' && typeof o.signature === 'string' && this.engine.restore?.thinking === 'placeholders') return value;
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(o)) {
        // Credentials the caller deliberately gives the provider for remote MCP servers.
        const credential =
          (key === 'mcp_servers' && k === 'authorization_token') || (o.type === 'mcp' && (k === 'headers' || k === 'authorization'));
        // Free-form keys (metadata maps) can hold personal data too.
        const mk = this.maskText(k, undefined, true);
        out[mk] = credential ? v : this.maskResidual(v, k);
      }
      return out as T;
    }
    return value;
  }

  private maskText(text: string, prefix: string | undefined, residual: boolean): string {
    if (!text) return text;
    this.checkSize(text);
    this.reserveLiteralTokens(text);
    // A residual pass sees already-masked text, which was never prepared; use NER spans only if they exist.
    const pre = residual ? (this.prepared.has(text) ? { precomputed: this.prepared.get(text) as RecognizedSpan[] } : {}) : this.precomputedFor(text);
    let entities = detectPii(text, {
      ...this.engine.detect,
      knownNames: this.knownNames,
      ...(prefix ? { prefix } : {}),
      ...pre,
    });
    if (residual) entities = entities.filter((e) => !this.isMaskedOutput(e.value));
    if (residual && entities.length === 0) return text;
    for (const n of nameComponents(entities)) this.knownNames.add(n);
    this.registerFullNames(entities, text);

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
    // Reserve placeholder-shaped literals from every leaf first, so a token issued
    // for an earlier field can never equal a literal in a later field.
    this.reserveDeep(value);
    return this.maskValueInner(value, key);
  }

  private maskValueInner<T>(value: T, key?: string): T {
    if (typeof value === 'string') {
      return this.mask(value, key ? `${humanizeKey(key)}: ` : undefined) as unknown as T;
    }
    if (Array.isArray(value)) return value.map((v) => this.maskValueInner(v, key)) as unknown as T;
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) out[k] = this.maskValueInner(v, k);
      return out as T;
    }
    return value;
  }

  private checkSize(text: string): void {
    if (text.length > this.engine.maxInputChars) throw new VelaInputTooLargeError(text.length, this.engine.maxInputChars);
  }

  private reserveDeep(value: unknown): void {
    if (typeof value === 'string') this.reserveLiteralTokens(value);
    else if (Array.isArray(value)) value.forEach((v) => this.reserveDeep(v));
    else if (value && typeof value === 'object') Object.values(value).forEach((v) => this.reserveDeep(v));
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

  /** Restore originals in a complete text (a content field unless `opts.field` says otherwise). */
  unmask(text: string, opts?: RestoreOptions): { text: string; restored: number } {
    return this.getRestorer().restore(text, this.restoreOptions(opts));
  }

  /**
   * Restore originals in every string of a JSON-like value. JSON-string fields
   * are escaped correctly, and each string is attributed to a field (content,
   * tool arguments, thinking) for the restore policy.
   */
  unmaskValue<T>(value: T, key?: string, field?: RestoreField): T {
    const f = fieldForKey(key, field);
    if (typeof value === 'string') {
      return this.getRestorer().restore(value, this.restoreOptions({ json: JSON_STRING_KEYS.has(key ?? ''), field: f ?? 'content' }))
        .text as unknown as T;
    }
    if (Array.isArray(value)) return value.map((v) => this.unmaskValue(v, key, f)) as unknown as T;
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) out[k] = this.unmaskValue(v, k, f);
      return out as T;
    }
    return value;
  }

  createStreamDeMasker(opts?: RestoreOptions): StreamRestorer {
    return this.getRestorer().createStream(this.restoreOptions(opts));
  }

  /** Value-free counts for audit events: entity occurrences by type, unique values by masking method. */
  stats(): { entities: Record<string, number>; actions: Record<string, number> } {
    const entities: Record<string, number> = {};
    for (const e of this.allEntities) entities[e.type] = (entities[e.type] ?? 0) + 1;
    const actions: Record<string, number> = {};
    for (const r of this.byMasked.values()) actions[r.method] = (actions[r.method] ?? 0) + 1;
    return { entities, actions };
  }

  /** Placeholders found in responses so far: how many were restored or kept, per field. */
  get restoreReport(): RestoreReport {
    return { restored: { ...this.report.restored }, kept: { ...this.report.kept } };
  }

  /** Apply the restore policy for the field and count what is restored or kept. */
  private restoreOptions(opts: RestoreOptions = {}): RestoreOptions {
    const field = opts.field ?? 'content';
    const keep = opts.keep ?? this.engine.restore?.[POLICY_KEY[field]] === 'placeholders';
    const bucket = keep ? this.report.kept : this.report.restored;
    return {
      ...opts,
      field,
      keep,
      onMatch: (rep) => {
        bucket[field]++;
        opts.onMatch?.(rep);
      },
    };
  }

  /** Snapshot as a (backwards-compatible) MaskResult. */
  toResult(text = ''): MaskResult {
    const mapping: Record<string, string> = {};
    const fpeMap: Record<string, string> = {};
    for (const r of this.byMasked.values()) {
      if (r.method === 'token') mapping[r.masked] = r.original;
      else if (r.method === 'fpe') fpeMap[r.original] = r.masked;
    }
    return { text, mapping, fpeMap, entities: this.entities, replacements: this.replacements };
  }

  private restorerBuiltFor = -1;

  /** Restorer over every replacement except redactions, which are never restored. */
  private getRestorer(): Restorer {
    if (!this.restorer || this.restorerBuiltFor !== this.byMasked.size) {
      this.restorer = new Restorer(this.replacements.filter((r) => r.method !== 'redact'));
      this.restorerBuiltFor = this.byMasked.size;
    }
    return this.restorer;
  }

  /**
   * Returns the masked form, or null if this built-in entity type is not
   * configured for masking. Custom types (from customDetectors / recognizers)
   * are always masked: nothing detected is passed through by accident.
   */
  private maskEntity(e: DetectedEntity, text: string): string | null {
    const isPerson = e.type === 'PERSON';
    const key = `${e.type}\u0000${isPerson ? e.value.toLowerCase() : e.value}`;
    const existing = this.byOriginal.get(key);
    if (existing) return existing.masked;

    const action = this.engine.actions?.[e.type];
    if (action === 'block') throw new VelaPolicyBlockedError(`policy "${this.engine.policyId ?? 'custom'}" blocks ${e.type}`, 422);
    if (action === 'allow') return null;
    const wantsFpe = action ? action === 'fpe' || action === 'fpe-synthetic' : this.engine.fpeTypes.includes(e.type);
    const wantsToken = action !== undefined || this.engine.tokenTypes.includes(e.type);
    if (!wantsFpe && !wantsToken && STANDARD_ENTITY_TYPES.has(e.type)) return null;

    // Partial mention of a known person ("Joseph" after "Joseph Mathew"): reuse that placeholder.
    const components = isPerson ? new Set(personComponents(e.value)) : null;
    if (components && components.size > 0 && this.linkPartialNames) {
      const matches = this.persons.filter((p) => [...components].every((c) => p.components.has(c)));
      if (matches.length === 1) {
        const rep = (matches[0] as { rep: Replacement }).rep;
        this.byOriginal.set(key, rep);
        return rep.masked;
      }
    }

    let rep: Replacement | null = null;
    if (wantsFpe) {
      let c = this.engine.fpe.encryptEntity(e.type, e.value, this.seed, e.metadata);
      if (c && action === 'fpe-synthetic') c = invalidateCheck(e.type, c);
      if (c && c !== e.value && !this.byMasked.has(c) && !text.includes(c)) {
        rep = { masked: c, original: e.value, type: e.type, method: 'fpe' };
      }
    }
    // Fail closed: anything that could not be format-preserved becomes a token.
    if (!rep) {
      rep = { masked: this.nextToken(e.type, text), original: e.value, type: e.type, method: action === 'redact' ? 'redact' : 'token' };
    }

    this.byOriginal.set(key, rep);
    this.byMasked.set(rep.masked, rep);
    if (components && components.size > 0) this.persons.push({ rep, components });
    return rep.masked;
  }

  private nextToken(type: EntityType, text: string): string {
    const base = String(type).toUpperCase().replace(/[^A-Z0-9_]/g, '_') || 'PII';
    let n = this.counters.get(base) ?? 0;
    let token: string;
    do {
      n++;
      token = `[${base}_${n}]`;
    } while (this.byMasked.has(token) || this.reserved.has(token) || text.includes(token));
    this.counters.set(base, n);
    return token;
  }

  /** True if `v` is, contains or is part of something this session issued (ciphertext or placeholder). */
  private isMaskedOutput(v: string): boolean {
    if (/\[[A-Z][A-Z0-9_]*_\d+\]/.test(v)) return true;
    for (const m of this.byMasked.keys()) if (m.includes(v) || v.includes(m)) return true;
    return false;
  }

  private reserveLiteralTokens(text: string): void {
    for (const m of text.matchAll(/\[[A-Z][A-Z0-9_]*_\d+\]/g)) this.reserved.add(m[0]);
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
