import { isIPv6 } from 'node:net';
import type { CustomDetector, DetectedEntity, EntityRecognizer, EntityType } from '../types.js';
import { validateVerhoeff } from './algorithms/verhoeff.js';
import { validateLuhn } from './algorithms/luhn.js';
import { validateIban } from './algorithms/iban.js';
import { validateGstin } from './algorithms/gstin.js';
import {
  STRONG_NAME_CONTEXT,
  isAmbiguousName,
  isKnownFirstName,
  isNameStopword,
} from './names.js';

interface ContextRule {
  /** Must match the text preceding the match (within `window` chars). */
  require?: RegExp;
  /** Rejects the match if it matches the preceding text… */
  reject?: RegExp;
  /** …unless this matches (overrides `reject`). */
  allow?: RegExp;
  window?: number;
}

interface PatternDef {
  type: EntityType;
  regex: RegExp;
  confidence: number;
  validator?: (match: string) => boolean;
  /** Validator is a checksum (skipped when validateChecksums=false). */
  checksum?: boolean;
  /** Use this capture group as the entity span. */
  group?: number;
  context?: ContextRule;
  metadata?: Record<string, unknown>;
  /** On validation failure, retry with trailing space-separated groups trimmed. */
  shrink?: boolean;
}

/** Entity types whose span may swallow smaller, fully-contained entities. */
const CONTAINER_TYPES: ReadonlySet<EntityType> = new Set(['ADDRESS']);

const digitCount = (s: string): number => (s.match(/\d/g) ?? []).length;

const PHONE_CUES = /\b(?:phone|ph|mobile|mob|cell|call|contact|whatsapp|wa|tel|telephone|sms|text|reach|dial|my number|number is)\b[^\n]{0,20}$/i;
const NON_PHONE_CUES =
  /\b(?:order|invoice|inv|txn|transaction|ref|reference|id|no|number|account|a\/c|acct|policy|ticket|tracking|awb|serial|sr|bill|receipt|utr|pnr|isbn|amount|rs|inr|usd|qty|code|batch|lot|sku|item|part|model|case)\b[^\n\w]{0,6}$|[₹$€£]\s*$/i;

const MONTH = '(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\\.?';
const DATE_RE = new RegExp(
  `\\b(?:\\d{1,2}[/.\\-]\\d{1,2}[/.\\-](?:\\d{4}|\\d{2})|\\d{4}[/.\\-]\\d{1,2}[/.\\-]\\d{1,2}|\\d{1,2}(?:st|nd|rd|th)?[ \\-]${MONTH},?[ \\-]\\d{4}|${MONTH} \\d{1,2}(?:st|nd|rd|th)?,? \\d{4})\\b`,
  'gi',
);

const STREET_SUFFIX =
  '(?:Road|Rd|Street|St|Marg|Nagar|Lane|Ln|Avenue|Ave|Colony|Layout|Cross|Main|Boulevard|Blvd|Drive|Highway|Hwy|Way|Place|Court|Circle|Enclave|Vihar|Bagh|Chowk|Gali|Peth|Puram|Halli|Palya|Extension|Ext)';
const ADDRESS_TAIL = '(?:,\\s*[A-Z][\\w.\\-]*(?:\\s+[A-Z][\\w.\\-]*){0,2}){0,3}(?:,?\\s*-?\\s*(?:[1-9]\\d{2}\\s?\\d{3}|\\d{5}(?:-\\d{4})?)(?!\\d))?';

const BUILTIN_PATTERNS: PatternDef[] = [
  // ── Secrets & credentials ────────────────────────────────────────────────
  {
    type: 'SECRET_KEY',
    regex:
      /\b(?:sk-proj-[A-Za-z0-9_-]+|sk-ant-[A-Za-z0-9_-]+|ghp_[A-Za-z0-9_]+|(?:gho|ghu|ghs|ghr)_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{20,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,72})\b/g,
    confidence: 1,
  },
  {
    type: 'SECRET_KEY',
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    confidence: 1,
  },
  { type: 'JWT', regex: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, confidence: 0.99 },

  // ── Indian identifiers ──────────────────────────────────────────────────
  {
    type: 'AADHAAR',
    regex: /(?<!\d[ -]?)[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?![ -]?\d)/g,
    confidence: 0.95,
    validator: (m) => validateVerhoeff(m.replace(/-/g, ' ')),
    checksum: true,
  },
  {
    type: 'GSTIN',
    regex: /\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/g,
    confidence: 0.97,
    validator: (m) => validateGstin(m, false),
  },
  { type: 'PAN', regex: /\b(?:[A-Z]{5}\d{4}[A-Z]|[a-z]{5}\d{4}[a-z])\b/g, confidence: 0.95 },
  { type: 'IFSC', regex: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g, confidence: 0.95 },
  {
    type: 'PASSPORT',
    regex: /\b[A-Z][0-9]{7}\b|\b(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b/g,
    confidence: 0.95,
    context: { require: /\bpassport\b[^\n]{0,25}$/i, window: 40 },
  },
  {
    type: 'UPI_ID',
    regex: /\b[A-Za-z0-9][A-Za-z0-9._-]{1,254}@[A-Za-z][A-Za-z0-9]{1,63}\b(?![.@\w-])/g,
    confidence: 0.95,
  },

  // ── Financial ───────────────────────────────────────────────────────────
  {
    type: 'CREDIT_CARD',
    regex:
      /(?<!\d[ -]?)(?:[2-68]\d{3}(?:[ -]?\d{4}){3}(?:[ -]?\d{1,3})?|3[47]\d{2}[ -]?\d{6}[ -]?\d{5}|[2-68]\d{3}[ -]?\d{4}[ -]?\d{4}[ -]?\d|[2-68]\d{12,18})(?![ -]?\d)/g,
    confidence: 0.95,
    validator: (m) => {
      const n = digitCount(m);
      return n >= 13 && n <= 19 && validateLuhn(m);
    },
    checksum: true,
  },
  {
    type: 'BANK_ACCOUNT',
    regex: /(?<![\d-])\d{9,18}(?![\d-])/g,
    confidence: 0.97,
    context: {
      require: /\b(?:a\/c|acct|account|acc|bank|savings|beneficiary)\b[^\n\d]{0,25}$/i,
      window: 50,
    },
  },
  {
    type: 'IBAN',
    regex: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g,
    confidence: 0.95,
    validator: (m) => validateIban(m),
    checksum: true,
    shrink: true,
  },

  // ── Contact ─────────────────────────────────────────────────────────────
  {
    type: 'EMAIL',
    regex: /(?<![\p{L}\p{N}._%+-])[\p{L}\p{N}._%+-]+@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)*\.\p{L}{2,}(?![\p{L}\p{N}])/gu,
    confidence: 0.98,
  },
  {
    // Indian mobile with +91 / 0 prefix
    type: 'PHONE',
    regex: /(?:\+91[ -]?(?:0[ -]?)?|(?<![\d+])0[ -]?)[6-9](?:[ -]?\d){9}(?![ -]?\d)/g,
    confidence: 0.96,
    metadata: { region: 'IN' },
  },
  {
    // Bare Indian mobile — masked unless clearly some other kind of number
    type: 'PHONE',
    regex: /(?<![\w+\-])[6-9](?:\d{9}|\d{4}[ -]\d{5}|\d{2}[ -]\d{3}[ -]\d{4})(?![\w-])/g,
    confidence: 0.9,
    metadata: { region: 'IN' },
    context: { reject: NON_PHONE_CUES, allow: PHONE_CUES, window: 40 },
  },
  {
    // Indian landline with STD code
    type: 'PHONE',
    regex: /(?<![\w+])0\d{2,4}[ -]\d{6,8}(?![\w-])/g,
    confidence: 0.88,
    validator: (m) => digitCount(m) >= 10 && digitCount(m) <= 11,
  },
  {
    // International E.164-style
    type: 'PHONE',
    regex: /(?<![\w+])\+[1-9](?:[ .-]?\(?\d\)?){6,14}(?![\w])/g,
    confidence: 0.93,
    validator: (m) => digitCount(m) >= 8 && digitCount(m) <= 15,
  },
  {
    // North American domestic
    type: 'PHONE',
    regex: /(?<![\w+])(?:\(\d{3}\)[ ]?|\d{3}[-. ])\d{3}[-. ]\d{4}(?![\w-])/g,
    confidence: 0.85,
    validator: (m) => {
      const d = m.replace(/\D/g, '');
      return /^[2-9]\d{2}[2-9]/.test(d);
    },
    metadata: { region: 'NANP' },
  },

  // ── Government IDs (US) ─────────────────────────────────────────────────
  {
    type: 'SSN',
    regex: /(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])/g,
    confidence: 0.9,
    validator: (m) => {
      const d = m.replace(/-/g, '');
      return !/^(000|666|9)/.test(d) && d.slice(3, 5) !== '00' && d.slice(5) !== '0000';
    },
  },
  {
    type: 'SSN',
    regex: /(?<!\d)\d{9}(?!\d)/g,
    confidence: 0.92,
    context: { require: /\b(?:ssn|social security(?: number| no\.?)?)\b[^\n\d]{0,15}$/i, window: 40 },
  },

  // ── Network ─────────────────────────────────────────────────────────────
  {
    type: 'IP_ADDRESS',
    regex:
      /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)/g,
    confidence: 0.85,
  },
  {
    type: 'IP_ADDRESS',
    regex: /(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?![\w:])/g,
    confidence: 0.9,
    validator: (m) => isIPv6(m) && /[0-9a-f]/i.test(m),
  },

  // ── Personal details ────────────────────────────────────────────────────
  {
    type: 'DATE_OF_BIRTH',
    regex: DATE_RE,
    confidence: 0.95,
    context: {
      require: /\b(?:dob|d\.o\.b\.?|date of birth|birth ?date|born(?: on)?|birthday)\b[^\n]{0,15}$/i,
      window: 40,
    },
  },
  {
    type: 'PIN_CODE',
    regex: /(?<!\d)[1-9]\d{2}\s?\d{3}(?!\d)/g,
    confidence: 0.9,
    context: { require: /\b(?:pin|pincode|pin code|postal code|post code)\s*(?:no\.?|code)?\s*[:#-]?\s*$/i, window: 25 },
  },
  {
    type: 'PIN_CODE',
    regex: /(?<!\d)\d{5}(?:-\d{4})?(?!\d)/g,
    confidence: 0.9,
    context: { require: /\bzip(?:\s*code)?\s*[:#-]?\s*$/i, window: 20 },
  },
  {
    // Labelled address: "Address: …" up to newline / next field
    type: 'ADDRESS',
    regex:
      /\b(?:address|addr\.?|residential address|permanent address|residing at|resident of|r\/o)\s*[:\-–]?\s*([^\n;|]{6,160}?)(?=\s*(?:[\n;|]|$|(?<!\b[A-Z])\.(?:\s|$)|[,.]?\s*\b(?:phone|ph|mobile|mob|tel|email|e-mail|pan|aadhaar|dob|d\.o\.b|date of birth|gstin|passport|account|a\/c)\b))/gi,
    confidence: 0.9,
    group: 1,
  },
  {
    // Street address: "12 MG Road, Indiranagar, Bengaluru 560038"
    type: 'ADDRESS',
    regex: new RegExp(
      `(?:\\b(?:Flat|House|H\\.? ?No\\.?|Plot|Door|Apt\\.?|Apartment|Unit|Suite|Room|Shop|Office)\\s*(?:No\\.?\\s*)?[\\w/-]+,?\\s+)?\\b\\d{1,5}[A-Za-z]?(?:[/-]\\d{1,4}[A-Za-z]?)?,?\\s+(?:(?:[A-Z][\\w'.\\-]*|\\d+(?:st|nd|rd|th))\\s+){0,4}${STREET_SUFFIX}\\b\\.?${ADDRESS_TAIL}`,
      'g',
    ),
    confidence: 0.85,
  },
  {
    type: 'ADDRESS',
    regex: new RegExp(`\\b(?:Sector|Phase|Block|Stage)[ -]\\d{1,3}[A-Z]?${ADDRESS_TAIL.replace('{0,3}', '{1,3}')}`, 'g'),
    confidence: 0.8,
  },
  {
    type: 'ORG',
    regex:
      /\b(?:[A-Z][A-Za-z0-9&'.-]*\s+){1,5}(?:Pvt\.?\s+Ltd\.?|Private\s+Limited|Limited|Ltd\.?|LLP|LLC|L\.L\.C\.|Inc\.?|Incorporated|Corp\.?|Corporation|GmbH|PLC|Pty\.?\s+Ltd\.?)(?!\w)/g,
    confidence: 0.85,
  },
];

const TITLE_SEQ = /(?<![\w@])[A-Z][a-z]+(?:['-][A-Za-z][a-z]+)?(?:[ ]+(?:[A-Z][a-z]+(?:['-][A-Za-z][a-z]+)?|[A-Z]\.))*(?![\w@])/g;
const UPPER_SEQ = /(?<![\w@])[A-Z]{2,}(?:[ ]+[A-Z]{2,}){1,3}(?![\w@])/g;

/** Heuristic person-name detection (see names.ts). */
function detectNames(text: string): DetectedEntity[] {
  const out: DetectedEntity[] = [];
  for (const re of [TITLE_SEQ, UPPER_SEQ]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const words: Array<{ w: string; start: number }> = [];
      const wr = /\S+/g;
      let wm: RegExpExecArray | null;
      while ((wm = wr.exec(m[0])) !== null) words.push({ w: wm[0], start: m.index + wm.index });
      // Process the sequence as sub-spans separated by stopwords.
      let i = 0;
      while (i < words.length) {
        while (i < words.length && isNameStopword((words[i] as { w: string }).w)) i++;
        let j = i;
        while (j < words.length && !isNameStopword((words[j] as { w: string }).w)) j++;
        if (j > i) {
          const span = words.slice(i, j).slice(0, 4);
          const first = span[0] as { w: string; start: number };
          const lastW = span[span.length - 1] as { w: string; start: number };
          const start = first.start;
          const end = lastW.start + lastW.w.length;
          const pre = text.slice(Math.max(0, start - 40), start);
          const strong = STRONG_NAME_CONTEXT.test(pre);
          const firstWord = first.w.replace(/\.$/, '');
          const gaz = isKnownFirstName(firstWord) && (span.length >= 2 || !isAmbiguousName(firstWord));
          const isInitialOnly = span.every((s) => /^[A-Z]\.$/.test(s.w));
          if ((strong || gaz) && !isInitialOnly) {
            out.push({ type: 'PERSON', start, end, value: text.slice(start, end), confidence: strong ? 0.9 : 0.8 });
          }
        }
        i = j;
      }
    }
  }
  return out;
}

export interface DetectOptions {
  glossary?: string[];
  validateChecksums?: boolean;
  customDetectors?: CustomDetector[];
  recognizers?: EntityRecognizer[];
  detectNames?: boolean;
  /** Name components already known from earlier text in the session; re-mentions are masked. */
  knownNames?: Iterable<string>;
  /**
   * Context text logically preceding `text` (e.g. a JSON key such as
   * "customer_name: "). Used for context cues only; never part of an entity.
   */
  prefix?: string;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function runPattern(p: PatternDef, text: string, validateChecksums: boolean, found: DetectedEntity[]): void {
  p.regex.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = p.regex.exec(text)) !== null) {
    if (m[0].length === 0) {
      p.regex.lastIndex++;
      continue;
    }
    let value = p.group !== undefined ? m[p.group] : m[0];
    if (value === undefined) continue;
    let start = p.group !== undefined ? m.index + m[0].indexOf(value) : m.index;
    value = value.replace(/[\s,.]+$/, '');
    if (!value) continue;

    if (p.context) {
      const pre = text.slice(Math.max(0, start - (p.context.window ?? 40)), start);
      const allowed = p.context.allow?.test(pre) ?? false;
      if (!allowed) {
        if (p.context.require && !p.context.require.test(pre)) continue;
        if (p.context.reject && p.context.reject.test(pre)) continue;
      }
    }

    if (p.validator && (validateChecksums || !p.checksum)) {
      let candidate = value;
      let ok = p.validator(candidate);
      while (!ok && p.shrink && /\s/.test(candidate)) {
        candidate = candidate.replace(/\s+\S+$/, '');
        ok = p.validator(candidate);
      }
      if (!ok) continue;
      value = candidate;
    }
    start = Math.max(start, 0);
    found.push({
      type: p.type,
      start,
      end: start + value.length,
      value,
      confidence: p.confidence,
      ...(p.metadata ? { metadata: { ...p.metadata } } : {}),
    });
  }
}

/** Resolve overlaps: highest confidence, then longest span, wins. Container types may absorb contained spans. */
function resolveOverlaps(found: DetectedEntity[]): DetectedEntity[] {
  const candidates = [...found].sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    const d = b.end - b.start - (a.end - a.start);
    if (d !== 0) return d;
    return a.start - b.start;
  });
  let selected: DetectedEntity[] = [];
  for (const c of candidates) {
    const overlapping = selected.filter((s) => c.start < s.end && c.end > s.start);
    if (overlapping.length === 0) {
      selected.push(c);
    } else if (CONTAINER_TYPES.has(c.type) && overlapping.every((s) => s.start >= c.start && s.end <= c.end)) {
      selected = selected.filter((s) => !overlapping.includes(s));
      selected.push(c);
    }
  }
  return selected.sort((a, b) => a.start - b.start);
}

/**
 * Detect PII entities in text.
 */
export function detectPii(text: string, options?: DetectOptions | string[]): DetectedEntity[] {
  if (!text) return [];
  const opts: DetectOptions = Array.isArray(options)
    ? { glossary: options, validateChecksums: true }
    : { validateChecksums: true, detectNames: true, ...options };

  const prefix = opts.prefix ?? '';
  const full = prefix + text;
  const validate = opts.validateChecksums !== false;
  const found: DetectedEntity[] = [];

  for (const p of BUILTIN_PATTERNS) runPattern(p, full, validate, found);

  for (const cd of opts.customDetectors ?? []) {
    runPattern(
      { type: cd.type, regex: cd.regex, confidence: cd.confidence ?? 0.9, ...(cd.validator ? { validator: cd.validator } : {}) },
      full,
      true,
      found,
    );
  }

  for (const term of opts.glossary ?? []) {
    if (!term || term.trim().length === 0) continue;
    const pre = /^\w/.test(term) ? '\\b' : '(?<=^|\\s|[^\\w])';
    const suf = /\w$/.test(term) ? '\\b' : '(?=\\s|[^\\w]|$)';
    const re = new RegExp(`${pre}${escapeRe(term)}${suf}`, 'gi');
    let m: RegExpExecArray | null;
    while ((m = re.exec(full)) !== null) {
      found.push({ type: 'CUSTOM', start: m.index, end: m.index + m[0].length, value: m[0], confidence: 1 });
    }
  }

  for (const rec of opts.recognizers ?? []) {
    for (const r of rec(full)) {
      if (r.end <= r.start || r.start < 0 || r.end > full.length) continue;
      found.push({ type: r.type, start: r.start, end: r.end, value: full.slice(r.start, r.end), confidence: r.confidence ?? 0.85 });
    }
  }

  if (opts.detectNames !== false) found.push(...detectNames(full));

  let selected = resolveOverlaps(found);

  // Re-mentions of known name components ("Rahul Sharma … Mr. Sharma … SHARMA").
  if (opts.detectNames !== false) {
    const components = new Set<string>(opts.knownNames ?? []);
    for (const e of selected) {
      if (e.type !== 'PERSON') continue;
      for (const w of e.value.split(/\s+/)) {
        if (w.length >= 3 && !isNameStopword(w) && /^[A-Za-z][A-Za-z'-]+$/.test(w)) components.add(w);
      }
    }
    if (components.size > 0) {
      const variants = new Set<string>();
      for (const c of components) {
        variants.add(c[0]!.toUpperCase() + c.slice(1).toLowerCase());
        variants.add(c.toUpperCase());
      }
      const re = new RegExp(`(?<![\\w@])(?:${[...variants].map(escapeRe).join('|')})(?![\\w@])`, 'g');
      const extra: DetectedEntity[] = [];
      let m: RegExpExecArray | null;
      while ((m = re.exec(full)) !== null) {
        const s = m.index;
        const e = s + m[0].length;
        if (!selected.some((x) => s < x.end && e > x.start)) {
          extra.push({ type: 'PERSON', start: s, end: e, value: m[0], confidence: 0.8 });
        }
      }
      if (extra.length) selected = [...selected, ...extra].sort((a, b) => a.start - b.start);
    }
  }

  if (!prefix) return selected;
  return selected
    .filter((e) => e.start >= prefix.length)
    .map((e) => ({ ...e, start: e.start - prefix.length, end: e.end - prefix.length }));
}

/** Extract name components (for session-level re-mention tracking). */
export function nameComponents(entities: DetectedEntity[]): string[] {
  const out: string[] = [];
  for (const e of entities) {
    if (e.type !== 'PERSON') continue;
    for (const w of e.value.split(/\s+/)) {
      if (w.length >= 3 && !isNameStopword(w) && /^[A-Za-z][A-Za-z'-]+$/.test(w)) out.push(w);
    }
  }
  return out;
}
