import type { MaskSession } from '../core/session.js';
import type { LlmApiFormat } from '../types.js';

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** Identify which LLM API a request path belongs to. */
export function detectApiFormat(pathname: string): LlmApiFormat | null {
  const p = pathname.replace(/\/+$/, '');
  if (/\/chat\/completions$/.test(p)) return 'openai-chat';
  if (/\/responses$/.test(p)) return 'openai-responses';
  if (/\/messages$/.test(p) && !/\/threads\//.test(p)) return 'anthropic-messages';
  return null;
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
    if (!p || typeof p !== 'object') return p;
    if (typeof p.text === 'string') return { ...p, text: visit(p.text, 'text') };
    return p;
  });
}

function walkOpenAiChat(body: Json, visit: Visit): Json {
  if (!Array.isArray(body.messages)) return body;
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
  return { ...body, messages };
}

function walkResponses(body: Json, visit: Visit): Json {
  const out: Json = { ...body };
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
  return walk(format, body as Json, (v, kind) => {
    if (kind === 'text' && typeof v === 'string') return session.mask(v);
    if (kind === 'json' && typeof v === 'string') return session.maskJsonString(v);
    return session.maskValue(v);
  }) as T;
}
