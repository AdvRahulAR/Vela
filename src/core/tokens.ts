import type { DetectedEntity } from '../types.js';

/**
 * Vela token masker for soft PII (names, locations, orgs, secrets).
 * Replaces detected soft PII with stable, reversible tokens like
 * `<PII type="PERSON" id="1"/>` so LLMs retain semantic context.
 */
export class TokenMasker {
  private map: Map<string, string> = new Map(); // token -> original
  private reverse: Map<string, string> = new Map(); // original -> token
  private counter = 0;

  /**
   * Mask soft PII entities in text with reversible tokens.
   */
  mask(
    text: string,
    entities: DetectedEntity[]
  ): { text: string; mapping: Record<string, string> } {
    // Sort descending by start index to prevent offset shifting during replacements
    const sorted = [...entities].sort((a, b) => b.start - a.start);
    let out = text;

    for (const e of sorted) {
      const original = text.slice(e.start, e.end);
      const token = this.tokenFor(original, e.type);
      out = out.slice(0, e.start) + token + out.slice(e.end);
    }

    return {
      text: out,
      mapping: Object.fromEntries(this.map),
    };
  }

  /**
   * Restore original values from tokens.
   */
  unmask(text: string, mapping: Record<string, string>): string {
    let out = text;
    for (const [token, original] of Object.entries(mapping)) {
      out = out.split(token).join(original);
    }
    return out;
  }

  /**
   * Reset internal session counters and mappings.
   */
  reset(): void {
    this.map.clear();
    this.reverse.clear();
    this.counter = 0;
  }

  private tokenFor(original: string, type: string): string {
    const existing = this.reverse.get(original);
    if (existing) return existing;

    const token = `<PII type="${type}" id="${this.counter}"/>`;
    this.counter++;
    this.map.set(token, original);
    this.reverse.set(original, token);
    return token;
  }
}
