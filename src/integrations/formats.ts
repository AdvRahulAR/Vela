import type { MaskSession } from '../core/session.js';
import type { LlmApiFormat } from '../types.js';

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** Identify which LLM API a request path belongs to. */
export function detectApiFormat(pathname: string): LlmApiFormat | null {
  const p = pathname.replace(/\/+$/, '');
  if (/\/chat\/completions$/.test(p)) return 'openai-chat';
  // input_tokens counts tokens for a Responses request: same body, same masking.
  if (/\/responses(\/input_tokens)?$/.test(p)) return 'openai-responses';
  // count_tokens takes a full Messages request body.
  if (/\/messages(\/count_tokens)?$/.test(p) && !/\/threads\//.test(p)) return 'anthropic-messages';
  return null;
}

/**
 * How Vela handles a request to a provider route:
 * - `llm`: a chat/messages/responses request, masked and restored;
 * - `fields`: top-level text fields (`input`, `prompt`) are masked; the JSON response is restored;
 * - `safe`: a method that carries no body (GET, HEAD, OPTIONS, DELETE, POST …/cancel), forwarded with any body dropped;
 * - `blocked`: anything else. Vela can't mask it, so it is not sent (fail closed).
 */
export type RouteClass =
  | { kind: 'llm'; format: LlmApiFormat }
  | { kind: 'fields'; fields: string[]; allowStream: boolean }
  | { kind: 'safe' }
  | { kind: 'blocked'; reason: string };

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'DELETE']);

export function classifyRoute(method: string, pathname: string): RouteClass {
  const m = method.toUpperCase();
  // Encoded paths could classify differently from how the provider routes them.
  if (pathname.includes('%')) return { kind: 'blocked', reason: 'percent-encoded paths are not accepted' };
  if (SAFE_METHODS.has(m)) return { kind: 'safe' };
  const p = pathname.replace(/\/+$/, '');
  // Cancel endpoints take no body (the body is dropped when forwarding).
  if (m === 'POST' && /\/cancel$/.test(p)) return { kind: 'safe' };
  if (m === 'POST') {
    const format = detectApiFormat(p);
    if (format) return { kind: 'llm', format };
    if (/\/(embeddings|moderations)$/.test(p)) return { kind: 'fields', fields: ['input'], allowStream: false };
    // Legacy text completions; streaming them is not supported, so it is rejected.
    if (/\/completions$/.test(p)) return { kind: 'fields', fields: ['prompt', 'suffix'], allowStream: false };
    // Ollama's native API returns NDJSON, which Vela can't restore; its /v1 OpenAI-compatible routes work.
    if (/^\/api\/(chat|generate|embed|embeddings)$/.test(p)) {
      return { kind: 'blocked', reason: "use Ollama's OpenAI-compatible /v1 endpoints" };
    }
    if (/\/batches(\/|$)/.test(p)) return { kind: 'blocked', reason: 'batch results arrive later and cannot be restored' };
    if (/\/(files|uploads)(\/|$)/.test(p)) return { kind: 'blocked', reason: 'file uploads cannot be masked' };
    if (/\/audio(\/|$)/.test(p)) return { kind: 'blocked', reason: 'audio cannot be masked' };
  }
  return { kind: 'blocked', reason: 'Vela does not know how to mask this route' };
}

/**
 * Leaf visitor: `text` = free text, `json` = a JSON-encoded string (tool args),
 * `value` = an arbitrary JSON value (Anthropic tool_use input).
 */
type Visit = (v: unknown, kind: 'text' | 'json' | 'value') => unknown;

function mapTextParts(parts: unknown, visit: Visit): unknown {
  if (typeof parts === 'string') return visit(parts, 'text');
  if (!Array.isArray(parts)) return parts;
  return parts.map((p: Json) => {
    if (typeof p === 'string') return visit(p, 'text');
    if (!p || typeof p !== 'object') return p;
    if (typeof p.text === 'string') return { ...p, text: visit(p.text, 'text') };
    return p;
  });
}

/** Tool/function definitions: descriptions and JSON-schema leaves (defaults, enums, examples) can hold PII. */
function walkTools(tools: unknown, visit: Visit): unknown {
  if (!Array.isArray(tools)) return tools;
  const one = (t: Json): Json => {
    if (!t || typeof t !== 'object') return t;
    const o: Json = { ...t };
    if (typeof o.description === 'string') o.description = visit(o.description, 'text');
    for (const k of ['input_schema', 'parameters']) {
      if (o[k] !== undefined && o[k] !== null) o[k] = visit(o[k], 'value');
    }
    if (o.function && typeof o.function === 'object') o.function = one(o.function);
    return o;
  };
  return tools.map(one);
}

function walkOpenAiChat(body: Json, visit: Visit): Json {
  const withTools: Json = body.tools !== undefined ? { ...body, tools: walkTools(body.tools, visit) } : body;
  if (!Array.isArray(body.messages)) return withTools;
  const messages = body.messages.map((msg: Json) => {
    if (!msg || typeof msg !== 'object') return msg;
    const m: Json = { ...msg };
    if (m.content !== undefined && m.content !== null) m.content = mapTextParts(m.content, visit);
    if (Array.isArray(m.tool_calls)) {
      m.tool_calls = m.tool_calls.map((tc: Json) =>
        typeof tc?.function?.arguments === 'string'
          ? { ...tc, function: { ...tc.function, arguments: visit(tc.function.arguments, 'json') } }
          : tc,
      );
    }
    if (typeof m.function_call?.arguments === 'string') {
      m.function_call = { ...m.function_call, arguments: visit(m.function_call.arguments, 'json') };
    }
    return m;
  });
  return { ...withTools, messages };
}

function walkResponses(body: Json, visit: Visit): Json {
  const out: Json = { ...body };
  if (out.tools !== undefined) out.tools = walkTools(out.tools, visit);
  if (typeof out.instructions === 'string') out.instructions = visit(out.instructions, 'text');
  if (typeof out.input === 'string') out.input = visit(out.input, 'text');
  else if (Array.isArray(out.input)) {
    out.input = out.input.map((item: Json) => {
      if (!item || typeof item !== 'object') return item;
      const it: Json = { ...item };
      if (it.content !== undefined && it.content !== null) it.content = mapTextParts(it.content, visit);
      if (typeof it.arguments === 'string') it.arguments = visit(it.arguments, 'json');
      if (typeof it.output === 'string') it.output = visit(it.output, 'json');
      else if (Array.isArray(it.output)) it.output = mapTextParts(it.output, visit);
      return it;
    });
  }
  return out;
}

function walkAnthropicBlocks(content: unknown, visit: Visit): unknown {
  if (typeof content === 'string') return visit(content, 'text');
  if (!Array.isArray(content)) return content;
  return content.map((b: Json) => {
    if (!b || typeof b !== 'object') return b;
    switch (b.type) {
      case 'text':
        return typeof b.text === 'string' ? { ...b, text: visit(b.text, 'text') } : b;
      case 'tool_use':
      case 'server_tool_use':
        return b.input !== undefined ? { ...b, input: visit(b.input, 'value') } : b;
      case 'tool_result':
        return b.content !== undefined ? { ...b, content: walkAnthropicBlocks(b.content, visit) } : b;
      case 'document':
        return b.source?.type === 'text' && typeof b.source.data === 'string'
          ? { ...b, source: { ...b.source, data: visit(b.source.data, 'text') } }
          : b;
      default:
        return b;
    }
  });
}

function walkAnthropic(body: Json, visit: Visit): Json {
  const out: Json = { ...body };
  if (out.system !== undefined) out.system = walkAnthropicBlocks(out.system, visit);
  if (out.tools !== undefined) out.tools = walkTools(out.tools, visit);
  if (Array.isArray(out.messages)) {
    out.messages = out.messages.map((m: Json) =>
      m && typeof m === 'object' && m.content !== undefined ? { ...m, content: walkAnthropicBlocks(m.content, visit) } : m,
    );
  }
  return out;
}

function walk(format: LlmApiFormat, body: Json, visit: Visit): Json {
  switch (format) {
    case 'openai-responses':
      return walkResponses(body, visit);
    case 'anthropic-messages':
      return walkAnthropic(body, visit);
    default:
      return walkOpenAiChat(body, visit);
  }
}

/**
 * Mask every user-supplied text field of an LLM request (prompts, system
 * prompts, tool-call arguments, tool results). Runs a learning pass first so
 * names introduced in later messages are also masked in earlier ones.
 */
export function maskLlmRequest<T extends object>(session: MaskSession, format: LlmApiFormat, body: T): T {
  walk(format, body as Json, (v, kind) => {
    if (kind === 'text' && typeof v === 'string') session.learn(v);
    else if (kind === 'json' && typeof v === 'string') session.learnValue(v, 'arguments');
    else session.learnValue(v);
    return v;
  });
  const walked = walk(format, body as Json, (v, kind) => {
    if (kind === 'text' && typeof v === 'string') return session.mask(v);
    if (kind === 'json' && typeof v === 'string') return session.maskJsonString(v);
    return session.maskValue(v);
  });
  // Backstop: fields the walk doesn't know (user, metadata, message names…) are masked too.
  return session.maskResidual(walked) as T;
}

/**
 * maskLlmRequest() preceded by the async recognizers (NER services), if any
 * are configured. All built-in integrations use this.
 */
export async function maskLlmRequestAsync<T extends object>(session: MaskSession, format: LlmApiFormat, body: T): Promise<T> {
  await session.prepareValue(body);
  return maskLlmRequest(session, format, body);
}

function maskNested(v: unknown, mask: (s: string) => string): unknown {
  if (typeof v === 'string') return mask(v);
  if (Array.isArray(v)) return v.map((x) => maskNested(x, mask));
  if (v && typeof v === 'object' && typeof (v as Json).text === 'string') return { ...(v as Json), text: mask((v as Json).text) };
  return v;
}

/**
 * Mask top-level text fields (`input`, `prompt`) of a `fields` route. Each
 * field may be a string or an array of strings; other values are left alone.
 */
export async function maskFieldsAsync<T extends Record<string, unknown>>(session: MaskSession, fields: string[], body: T): Promise<T> {
  const out: Record<string, unknown> = { ...body };
  await session.prepareValue(body);
  for (const f of fields) {
    const v = out[f];
    if (typeof v === 'string') out[f] = session.mask(v);
    // Arrays may hold strings, token ids, nested arrays or multimodal parts ({ type: 'text', text }).
    else if (Array.isArray(v)) out[f] = maskNested(v, (x) => session.mask(x));
  }
  return session.maskResidual(out) as T;
}

/** Content-part types that carry text Vela masks (everything else is non-text). */
const TEXT_PART_TYPES = new Set([
  'text', 'input_text', 'output_text', 'tool_use', 'server_tool_use', 'tool_result', 'thinking', 'redacted_thinking',
  'function_call', 'function_call_output', 'message', 'reasoning', 'refusal', 'search_result',
  'web_search_tool_result', 'web_fetch_tool_result', 'code_execution_tool_result',
]);
/** Keys that mark an object as a content part rather than a setting such as `{ type: 'auto' }`. */
const PART_KEYS = ['content', 'source', 'image_url', 'input_audio', 'file', 'file_id', 'file_data', 'file_url', 'text'];

/**
 * Types of non-text content (images, audio, files, non-text documents) in a
 * request, for the `nonText: 'block'` policy. Empty when there are none.
 */
export function findNonText(body: unknown): string[] {
  const found = new Set<string>();
  const visit = (v: unknown): void => {
    if (Array.isArray(v)) return v.forEach(visit);
    if (!v || typeof v !== 'object') return;
    const o = v as Json;
    if (typeof o.type === 'string' && PART_KEYS.some((k) => k in o)) {
      const textDoc = o.type === 'document' && o.source?.type === 'text';
      if (!TEXT_PART_TYPES.has(o.type) && !textDoc) found.add(o.type);
    }
    for (const x of Object.values(o)) if (x && typeof x === 'object') visit(x);
  };
  visit(body);
  return [...found];
}
