import type { MaskResult, StreamDeMasker } from '../types.js';

interface ReplacementPair {
  target: string;
  replacement: string;
}

/**
 * Buffer-aware streaming de-masker.
 * Handles tokens and FPE ciphertexts that are split across chunk boundaries
 * during streaming LLM completions.
 */
export class TokenStreamDeMasker implements StreamDeMasker {
  private buffer = '';
  private pairs: ReplacementPair[] = [];
  private maxTargetLength = 0;

  constructor(maskResult: MaskResult | MaskResult[]) {
    const results = Array.isArray(maskResult) ? maskResult : [maskResult];
    const pairMap = new Map<string, string>();

    for (const r of results) {
      // Token replacements
      for (const [token, original] of Object.entries(r.mapping)) {
        pairMap.set(token, original);
      }
      // FPE ciphertext replacements
      for (const [original, cipher] of Object.entries(r.fpeMap)) {
        pairMap.set(cipher, original);
      }
    }

    // Sort by length descending to match longest tokens first
    this.pairs = Array.from(pairMap.entries())
      .map(([target, replacement]) => ({ target, replacement }))
      .sort((a, b) => b.target.length - a.target.length);

    this.maxTargetLength = this.pairs.reduce((max, p) => Math.max(max, p.target.length), 0);
  }

  /**
   * Process a text chunk and return the unmasked text safe to emit immediately.
   */
  feed(chunk: string): string {
    if (!chunk) return '';
    this.buffer += chunk;

    // Apply any complete matches in the buffer
    this.applyReplacements();

    // Check if the end of the buffer matches a prefix of any target
    const holdbackLength = this.computeHoldbackLength();
    if (holdbackLength === 0) {
      const output = this.buffer;
      this.buffer = '';
      return output;
    }

    const safeLength = this.buffer.length - holdbackLength;
    if (safeLength > 0) {
      const output = this.buffer.slice(0, safeLength);
      this.buffer = this.buffer.slice(safeLength);
      return output;
    }

    return '';
  }

  /**
   * Flush remaining buffered characters at the end of the stream.
   */
  flush(): string {
    this.applyReplacements();
    const remaining = this.buffer;
    this.buffer = '';
    return remaining;
  }

  private applyReplacements(): void {
    let replaced = true;
    while (replaced) {
      replaced = false;
      for (const { target, replacement } of this.pairs) {
        const idx = this.buffer.indexOf(target);
        if (idx !== -1) {
          this.buffer =
            this.buffer.slice(0, idx) +
            replacement +
            this.buffer.slice(idx + target.length);
          replaced = true;
          break; // restart check after mutation
        }
      }
    }
  }

  private computeHoldbackLength(): number {
    if (this.pairs.length === 0 || this.buffer.length === 0) return 0;

    const maxCheck = Math.min(this.buffer.length, this.maxTargetLength - 1);
    for (let len = maxCheck; len > 0; len--) {
      const suffix = this.buffer.slice(-len);
      for (const { target } of this.pairs) {
        if (target.startsWith(suffix)) {
          return len;
        }
      }
    }

    return 0;
  }
}

/**
 * Transform an SSE (Server-Sent Events) stream line-by-line, de-masking
 * delta contents in real time.
 */
export function createSseDeMasker(maskResults: MaskResult | MaskResult[]): (rawSseChunk: string) => string {
  const deMasker = new TokenStreamDeMasker(maskResults);
  let lineBuffer = '';

  return (chunk: string): string => {
    lineBuffer += chunk;
    const lines = lineBuffer.split('\n');
    lineBuffer = lines.pop() ?? ''; // keep trailing partial line

    const outputLines: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) {
        outputLines.push(line);
        continue;
      }

      const dataStr = trimmed.slice(5).trim();
      if (dataStr === '[DONE]') {
        // If lineBuffer held any previous unparsed line, it has already been processed because lines was split by \n.
        // Flush any held back characters from deMasker before emitting [DONE]
        const remaining = deMasker.flush();
        if (remaining) {
          // If there was held back content, inject a synthetic delta before [DONE]
          const syntheticEvent = `data: ${JSON.stringify({
            choices: [{ delta: { content: remaining } }],
          })}\n\n`;
          outputLines.push(syntheticEvent);
        }
        outputLines.push(line);
        continue;
      }

      try {
        const parsed = JSON.parse(dataStr);
        const delta = parsed.choices?.[0]?.delta;
        if (delta && typeof delta.content === 'string') {
          const unmaskedPart = deMasker.feed(delta.content);
          delta.content = unmaskedPart;
          outputLines.push(`data: ${JSON.stringify(parsed)}`);
        } else {
          outputLines.push(line);
        }
      } catch {
        outputLines.push(line);
      }
    }

    return outputLines.length > 0 ? outputLines.join('\n') + '\n' : '';
  };
}
