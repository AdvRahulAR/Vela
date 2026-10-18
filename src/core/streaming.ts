import { Restorer, replacementsFrom, type RestoreField, type RestoreOptions, type StreamRestorer } from './matcher.js';
import type { LlmApiFormat, MaskResult, StreamDeMasker } from '../types.js';

/** Anything that can restore values: a MaskSession, or a set of legacy MaskResults. */
export interface RestoreSource {
  createStreamDeMasker(opts?: RestoreOptions): StreamRestorer;
  unmaskValue<T>(value: T, key?: string, field?: RestoreField): T;
}

const JSON_STRING_KEYS = new Set(['arguments', 'partial_json']);
const TOOL_ARG_KEYS = new Set(['arguments', 'partial_json', 'input']);
const THINKING_KEYS = new Set(['thinking', 'reasoning_content', 'reasoning', 'summary']);

/**
 * The response field a JSON key starts: tool-call arguments (`arguments`,
 * `partial_json`, Anthropic `tool_use.input`), model reasoning, or inherited
 * from the parent (content at the top level).
 */
export function fieldForKey(key: string | undefined, parent?: RestoreField): RestoreField | undefined {
  if (parent && parent !== 'content') return parent;
  if (key && TOOL_ARG_KEYS.has(key)) return 'tool_args';
  if (key && THINKING_KEYS.has(key)) return 'thinking';
  return parent;
}

/** Adapter turning legacy MaskResult(s) into a RestoreSource. */
export class ResultRestoreSource implements RestoreSource {
  private readonly restorer: Restorer;
  constructor(results: MaskResult | MaskResult[]) {
    this.restorer = new Restorer(replacementsFrom(results));
  }
  createStreamDeMasker(opts?: RestoreOptions): StreamRestorer {
    return this.restorer.createStream(opts);
  }
  unmaskValue<T>(value: T, key?: string): T {
    if (typeof value === 'string') {
      return this.restorer.restore(value, { json: JSON_STRING_KEYS.has(key ?? '') }).text as unknown as T;
    }
    if (Array.isArray(value)) return value.map((v) => this.unmaskValue(v, key)) as unknown as T;
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) out[k] = this.unmaskValue(v, k);
      return out as T;
    }
    return value;
  }
}

export function toRestoreSource(src: RestoreSource | MaskResult | MaskResult[]): RestoreSource {
  if (src && typeof (src as RestoreSource).createStreamDeMasker === 'function') return src as RestoreSource;
  return new ResultRestoreSource(src as MaskResult | MaskResult[]);
}

/**
 * Backwards-compatible chunk-boundary-aware de-masker for a plain text stream.
 */
export class TokenStreamDeMasker implements StreamDeMasker {
  private readonly inner: StreamRestorer;
  constructor(maskResult: MaskResult | MaskResult[], opts?: RestoreOptions) {
    this.inner = new Restorer(replacementsFrom(maskResult)).createStream(opts);
  }
  feed(chunk: string): string {
    return this.inner.feed(chunk);
  }
  flush(): string {
    return this.inner.flush();
  }
}

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

class Lanes {
  private readonly lanes = new Map<string, StreamRestorer>();
  constructor(private readonly src: RestoreSource) {}
  get(key: string, json = false, field: RestoreField = json ? 'tool_args' : 'content'): StreamRestorer {
    let l = this.lanes.get(key);
    if (!l) {
      l = this.src.createStreamDeMasker({ json, field });
      this.lanes.set(key, l);
    }
    return l;
  }
  flush(key: string): string {
    const l = this.lanes.get(key);
    if (!l) return '';
    this.lanes.delete(key);
    return l.flush();
  }
  keys(prefix = ''): string[] {
    return [...this.lanes.keys()].filter((k) => k.startsWith(prefix));
  }
}

/** Common interface for provider-specific stream event unmaskers. */
export interface EventUnmasker {
  /** Transform one parsed stream event; may return extra synthetic events. */
  process(event: Json): Json[];
  /** Emit events for anything still buffered at end of stream. */
  finish(): Json[];
}

/**
 * OpenAI Chat Completions chunks: one lane per choice for content/refusal and one
 * per (choice, tool call) for function arguments. Lanes are flushed on that
 * choice's finish_reason so nothing is held past the end of a choice.
 */
export class OpenAiChatStreamUnmasker implements EventUnmasker {
  private readonly lanes: Lanes;
  private template: Json = {};
  constructor(src: RestoreSource) {
    this.lanes = new Lanes(src);
  }

  process(chunk: Json): Json[] {
    if (!chunk || !Array.isArray(chunk.choices)) return [chunk];
    this.template = { id: chunk.id, object: chunk.object, created: chunk.created, model: chunk.model };
    const choices = chunk.choices.map((choice: Json, i: number) => {
      const idx = choice.index ?? i;
      const delta: Json | undefined = choice.delta ? { ...choice.delta } : undefined;
      if (delta) {
        for (const field of ['content', 'refusal', 'reasoning_content']) {
          if (typeof delta[field] === 'string') {
            const kind = field === 'reasoning_content' ? 'thinking' : 'content';
            delta[field] = this.lanes.get(`${idx}|${field}`, false, kind).feed(delta[field]);
          }
        }
        if (Array.isArray(delta.tool_calls)) {
          delta.tool_calls = delta.tool_calls.map((tc: Json, j: number) => {
            const args = tc.function?.arguments;
            if (typeof args !== 'string') return tc;
            const lane = this.lanes.get(`${idx}|tool|${tc.index ?? j}`, true);
            return { ...tc, function: { ...tc.function, arguments: lane.feed(args) } };
          });
        }
      }
      const out: Json = { ...choice, ...(delta ? { delta } : {}) };
      if (choice.finish_reason) this.flushChoice(idx, out);
      return out;
    });
    return [{ ...chunk, choices }];
  }

  private flushChoice(idx: number, choice: Json): void {
    const delta: Json = (choice.delta = { ...(choice.delta ?? {}) });
    for (const key of this.lanes.keys(`${idx}|`)) {
      const rest = this.lanes.flush(key);
      if (!rest) continue;
      const parts = key.split('|');
      if (parts[1] === 'tool') {
        const tIdx = Number(parts[2]);
        const calls: Json[] = (delta.tool_calls = [...(delta.tool_calls ?? [])]);
        const existing = calls.find((c) => (c.index ?? 0) === tIdx);
        if (existing) {
          existing.function = { ...(existing.function ?? {}), arguments: (existing.function?.arguments ?? '') + rest };
        } else calls.push({ index: tIdx, function: { arguments: rest } });
      } else {
        const field = parts[1] as string;
        delta[field] = (delta[field] ?? '') + rest;
      }
    }
  }

  finish(): Json[] {
    const idxs = new Set(this.lanes.keys().map((k) => Number(k.split('|')[0])));
    const choices: Json[] = [];
    for (const idx of idxs) {
      const choice: Json = { index: idx, delta: {}, finish_reason: null };
      this.flushChoice(idx, choice);
      if (Object.keys(choice.delta).length) choices.push(choice);
    }
    if (!choices.length) return [];
    return [
      {
        id: this.template.id ?? 'vela-stream-flush',
        object: this.template.object ?? 'chat.completion.chunk',
        created: this.template.created ?? Math.floor(Date.now() / 1000),
        ...(this.template.model ? { model: this.template.model } : {}),
        choices,
      },
    ];
  }
}

const ANTHROPIC_DELTA_FIELDS: Record<string, string> = {
  text_delta: 'text',
  thinking_delta: 'thinking',
  input_json_delta: 'partial_json',
};

/** Anthropic Messages streaming events. */
export class AnthropicStreamUnmasker implements EventUnmasker {
  private readonly lanes: Lanes;
  private readonly deltaType = new Map<number, string>();
  constructor(private readonly src: RestoreSource) {
    this.lanes = new Lanes(src);
  }

  process(ev: Json): Json[] {
    if (!ev || typeof ev !== 'object') return [ev];
    if (ev.type === 'content_block_delta' && ev.delta) {
      const field = ANTHROPIC_DELTA_FIELDS[ev.delta.type as string];
      if (field && typeof ev.delta[field] === 'string') {
        this.deltaType.set(ev.index, ev.delta.type);
        const kind = field === 'partial_json' ? 'tool_args' : field === 'thinking' ? 'thinking' : 'content';
        const lane = this.lanes.get(String(ev.index), field === 'partial_json', kind);
        return [{ ...ev, delta: { ...ev.delta, [field]: lane.feed(ev.delta[field]) } }];
      }
      return [this.src.unmaskValue(ev)];
    }
    if (ev.type === 'content_block_stop') return [...this.flushIndex(ev.index), ev];
    if (ev.type === 'message_stop') return [...this.finish(), ev];
    return [this.src.unmaskValue(ev)];
  }

  private flushIndex(index: number): Json[] {
    const rest = this.lanes.flush(String(index));
    if (!rest) return [];
    const dt = this.deltaType.get(index) ?? 'text_delta';
    return [{ type: 'content_block_delta', index, delta: { type: dt, [ANTHROPIC_DELTA_FIELDS[dt] ?? 'text']: rest } }];
  }

  finish(): Json[] {
    return this.lanes.keys().flatMap((k) => this.flushIndex(Number(k)));
  }
}

/** OpenAI Responses API streaming events. */
export class ResponsesStreamUnmasker implements EventUnmasker {
  private readonly lanes: Lanes;
  private readonly templates = new Map<string, Json>();
  constructor(private readonly src: RestoreSource) {
    this.lanes = new Lanes(src);
  }

  private key(base: string, ev: Json): string {
    return [base, ev.item_id ?? '', ev.output_index ?? '', ev.content_index ?? '', ev.summary_index ?? ''].join('|');
  }

  process(ev: Json): Json[] {
    if (!ev || typeof ev.type !== 'string') return [ev];
    if (ev.type.endsWith('.delta') && typeof ev.delta === 'string') {
      const base = ev.type.slice(0, -'.delta'.length);
      const key = this.key(base, ev);
      this.templates.set(key, ev);
      const kind = base.includes('arguments') ? 'tool_args' : base.includes('reasoning') ? 'thinking' : 'content';
      return [{ ...ev, delta: this.lanes.get(key, base.includes('arguments'), kind).feed(ev.delta) }];
    }
    if (ev.type.endsWith('.done')) {
      const base = ev.type.slice(0, -'.done'.length);
      return [...this.flushKey(this.key(base, ev)), this.src.unmaskValue(ev)];
    }
    return [this.src.unmaskValue(ev)];
  }

  private flushKey(key: string): Json[] {
    const rest = this.lanes.flush(key);
    const tpl = this.templates.get(key);
    if (!rest || !tpl) return [];
    return [{ ...tpl, delta: rest }];
  }

  finish(): Json[] {
    return this.lanes.keys().flatMap((k) => this.flushKey(k));
  }
}

export function createEventUnmasker(format: LlmApiFormat, src: RestoreSource): EventUnmasker {
  switch (format) {
    case 'anthropic-messages':
      return new AnthropicStreamUnmasker(src);
    case 'openai-responses':
      return new ResponsesStreamUnmasker(src);
    default:
      return new OpenAiChatStreamUnmasker(src);
  }
}

// ── Server-Sent Events plumbing ──────────────────────────────────────────────

interface SseEvent {
  event?: string;
  data?: string;
  other: string[];
}

class SseParser {
  private buf = '';
  push(chunk: string): SseEvent[] {
    this.buf += chunk;
    const out: SseEvent[] = [];
    let m: RegExpExecArray | null;
    const sep = /\r?\n\r?\n/g;
    let last = 0;
    while ((m = sep.exec(this.buf)) !== null) {
      out.push(parseEvent(this.buf.slice(last, m.index)));
      last = m.index + m[0].length;
    }
    this.buf = this.buf.slice(last);
    return out;
  }
  end(): SseEvent[] {
    const rest = this.buf;
    this.buf = '';
    return rest.trim() ? [parseEvent(rest)] : [];
  }
}

function parseEvent(block: string): SseEvent {
  const ev: SseEvent = { other: [] };
  const data: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
    else if (line.startsWith('event:')) ev.event = line.slice(6).trim();
    else if (line.length) ev.other.push(line);
  }
  if (data.length) ev.data = data.join('\n');
  return ev;
}

function serialize(ev: SseEvent): string {
  const lines = [...ev.other];
  if (ev.event !== undefined) lines.push(`event: ${ev.event}`);
  if (ev.data !== undefined) for (const l of ev.data.split('\n')) lines.push(`data: ${l}`);
  return lines.join('\n') + '\n\n';
}

export interface SseTransformer {
  push(chunk: string): string;
  end(): string;
}

/** Transform a raw SSE text stream, restoring masked values in every event. */
export function createSseTransformer(
  format: LlmApiFormat,
  src: RestoreSource | MaskResult | MaskResult[],
): SseTransformer {
  const parser = new SseParser();
  const unmasker = createEventUnmasker(format, toRestoreSource(src));
  let finished = false;

  const emitObjects = (objs: Json[], template: SseEvent): string =>
    objs
      .map((o) =>
        serialize({
          other: template.other,
          ...(template.event !== undefined ? { event: typeof o?.type === 'string' && format !== 'openai-chat' ? o.type : template.event } : {}),
          data: JSON.stringify(o),
        }),
      )
      .join('');

  const handle = (events: SseEvent[]): string => {
    let out = '';
    for (const ev of events) {
      if (ev.data === undefined) {
        out += serialize(ev);
        continue;
      }
      if (ev.data.trim() === '[DONE]') {
        if (!finished) {
          finished = true;
          out += emitObjects(unmasker.finish(), { other: [] });
        }
        out += serialize(ev);
        continue;
      }
      let parsed: Json;
      try {
        parsed = JSON.parse(ev.data);
      } catch {
        out += serialize(ev);
        continue;
      }
      out += emitObjects(unmasker.process(parsed), ev);
    }
    return out;
  };

  return {
    push: (chunk) => handle(parser.push(chunk)),
    end: () => {
      let out = handle(parser.end());
      if (!finished) {
        finished = true;
        const rest = unmasker.finish();
        if (rest.length) {
          out += emitObjects(rest, format === 'openai-chat' ? { other: [] } : { other: [], event: '' });
        }
      }
      return out;
    },
  };
}

/**
 * Backwards-compatible OpenAI Chat SSE de-masker. Prefer createSseTransformer(),
 * which also exposes end() for flushing at stream close.
 */
export function createSseDeMasker(maskResults: MaskResult | MaskResult[]): (rawSseChunk: string) => string {
  const t = createSseTransformer('openai-chat', maskResults);
  return (chunk: string) => t.push(chunk);
}
