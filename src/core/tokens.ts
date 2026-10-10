import type { DetectedEntity } from '../types.js';

/**
 * Low-level token masker for soft PII. Replaces entities with reversible,
 * JSON-safe placeholders such as `[PERSON_1]` or `[EMAIL_2]`.
 *
 * Prefer `Vela#createSession()`, which also handles FPE and multi-message
 * consistency; this class is kept for backwards compatibility.
 */
export class TokenMasker {
  private map: Map<string, string> = new Map(); // token -> original
  private reverse: Map<string, string> = new Map(); // type+original -> token
  private counters: Map<string, number> = new Map();

  mask(text: string, entities: DetectedEntity[]): { text: string; mapping: Record<string, string> } {
    const sorted = [...entities].sort((a, b) => a.start - b.start);
    let out = '';
    let pos = 0;
    for (const e of sorted) {
      if (e.start < pos) continue;
      out += text.slice(pos, e.start) + this.tokenFor(text.slice(e.start, e.end), String(e.type), text);
      pos = e.end;
    }
    return { text: out + text.slice(pos), mapping: Object.fromEntries(this.map) };
  }

  unmask(text: string, mapping: Record<string, string>): string {
    let out = text;
    for (const [token, original] of Object.entries(mapping)) out = out.split(token).join(original);
    return out;
  }

  reset(): void {
    this.map.clear();
    this.reverse.clear();
    this.counters.clear();
  }

  private tokenFor(original: string, type: string, text: string): string {
    const key = `${type}\u0000${original}`;
    const existing = this.reverse.get(key);
    if (existing) return existing;
    const base = type.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    let n = this.counters.get(base) ?? 0;
    let token: string;
    do {
      n++;
      token = `[${base}_${n}]`;
    } while (this.map.has(token) || text.includes(token));
    this.counters.set(base, n);
    this.map.set(token, original);
    this.reverse.set(key, token);
    return token;
  }
}
