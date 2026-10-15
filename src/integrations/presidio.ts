import type { AsyncEntityRecognizer, EntityType, RecognizedSpan } from '../types.js';

export interface PresidioRecognizerOptions {
  /** Base URL of a Presidio Analyzer service, e.g. http://localhost:5002 */
  url: string;
  /** Language code sent to Presidio. Default: 'en'. */
  language?: string;
  /** Presidio entity types to request. Default: PERSON, LOCATION, ORGANIZATION, NRP. */
  entities?: string[];
  /** Minimum Presidio score to keep. Default: 0.5. */
  scoreThreshold?: number;
  /**
   * Presidio entity type → Vela entity type. Unmapped types keep their Presidio
   * name and, as custom types, are always masked as placeholders.
   */
  typeMap?: Record<string, EntityType>;
  /** Parallel /analyze calls. Default: 8. */
  concurrency?: number;
  /** Extra HTTP headers (e.g. authentication for a hosted analyzer). */
  headers?: Record<string, string>;
  /** fetch implementation (for tests or custom agents). Default: global fetch. */
  fetchImpl?: typeof fetch;
}

const DEFAULT_TYPE_MAP: Record<string, EntityType> = {
  PERSON: 'PERSON',
  LOCATION: 'LOCATION',
  ORGANIZATION: 'ORG',
  NRP: 'NRP',
};

interface PresidioResult {
  entity_type: string;
  start: number;
  end: number;
  score: number;
}

/**
 * Presidio (Python) reports offsets in Unicode code points; JavaScript strings
 * index UTF-16 code units. Returns a table from code-point index to UTF-16 index
 * (length = code points + 1).
 */
export function codePointToUtf16Index(text: string): number[] {
  const map: number[] = [];
  let u = 0;
  for (const ch of text) {
    map.push(u);
    u += ch.length;
  }
  map.push(u);
  return map;
}

async function pool<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i] as T, i);
    }
  });
  await Promise.all(workers);
  return out;
}

/**
 * Async recognizer backed by a Microsoft Presidio Analyzer service
 * (`POST /analyze`). Use with `VelaConfig.asyncRecognizers`:
 *
 * ```ts
 * new Vela({ asyncRecognizers: [presidioRecognizer({ url: 'http://localhost:5002' })] });
 * ```
 *
 * Any HTTP or network error rejects, so with the default
 * `recognizerFailure: 'block'` the request is not forwarded.
 */
export function presidioRecognizer(opts: PresidioRecognizerOptions): AsyncEntityRecognizer {
  const base = opts.url.replace(/\/+$/, '');
  const doFetch = opts.fetchImpl ?? fetch;
  const typeMap = { ...DEFAULT_TYPE_MAP, ...(opts.typeMap ?? {}) };
  const entities = opts.entities ?? ['PERSON', 'LOCATION', 'ORGANIZATION', 'NRP'];
  const threshold = opts.scoreThreshold ?? 0.5;

  return async (texts: string[], signal: AbortSignal): Promise<RecognizedSpan[][]> =>
    pool(texts, opts.concurrency ?? 8, async (text) => {
      const res = await doFetch(`${base}/analyze`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(opts.headers ?? {}) },
        body: JSON.stringify({ text, language: opts.language ?? 'en', entities, score_threshold: threshold }),
        signal,
      });
      if (!res.ok) throw new Error(`Presidio /analyze returned HTTP ${res.status}`);
      const results = (await res.json()) as PresidioResult[];
      if (!Array.isArray(results)) throw new Error('Presidio /analyze returned an unexpected body');
      const idx = codePointToUtf16Index(text);
      const spans: RecognizedSpan[] = [];
      for (const r of results) {
        if (typeof r.start !== 'number' || typeof r.end !== 'number' || r.score < threshold) continue;
        const start = idx[r.start];
        const end = idx[r.end];
        if (start === undefined || end === undefined || end <= start) continue;
        spans.push({ type: typeMap[r.entity_type] ?? r.entity_type, start, end, confidence: Math.min(0.99, Math.max(0.5, r.score)) });
      }
      return spans;
    });
}
