import { validateVerhoeff } from './algorithms/verhoeff.js';
import { validateLuhn } from './algorithms/luhn.js';
import { validateIban } from './algorithms/iban.js';
import type { CustomDetector, DetectedEntity, EntityType } from '../types.js';

interface InternalPattern {
  type: EntityType;
  regex: RegExp;
  confidence: number;
  validator?: (match: string) => boolean;
}


const BUILTIN_PATTERNS: InternalPattern[] = [
  // Secrets & API Keys (OpenAI sk-proj-/sk-, Anthropic sk-ant-, GitHub ghp_, AWS AKIA, Slack)
  {
    type: 'SECRET_KEY',
    regex: /\b(?:sk-proj-[A-Za-z0-9_-]+|sk-ant-[A-Za-z0-9_-]+|ghp_[A-Za-z0-9_]+|(?:gho|ghu|ghs|ghr)_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z]{10,48})\b/g,
    confidence: 1.0,
  },
  // JWT
  {
    type: 'JWT',
    regex: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    confidence: 0.99,
  },
  // Aadhaar: 12 digits (starting 2-9), optional space separator
  {
    type: 'AADHAAR',
    regex: /\b[2-9]\d{3}[ ]?\d{4}[ ]?\d{4}\b/g,
    confidence: 0.95,
    validator: (m) => validateVerhoeff(m),
  },
  // Credit Cards: 13-19 digits with Luhn checksum
  {
    type: 'CREDIT_CARD',
    regex: /\b(?:\d{4}[ -]?){3}\d{4}\b|\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b/g,
    confidence: 0.95,
    validator: (m) => validateLuhn(m),
  },
  // PAN: 5 uppercase letters + 4 digits + 1 uppercase letter
  {
    type: 'PAN',
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
    confidence: 0.95,
  },
  // GSTIN: 2 digits + 10-char PAN + 1 check + 2
  {
    type: 'GSTIN',
    regex: /\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/g,
    confidence: 0.95,
    validator: (m) => {
      const stateCode = parseInt(m.slice(0, 2), 10);
      return (stateCode >= 1 && stateCode <= 38) || stateCode === 97 || stateCode === 99;
    },
  },
  // Email (RFC-compliant without backtracking vulnerability)
  {
    type: 'EMAIL',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g,
    confidence: 0.98,
  },
  // Phone: Indian format (+91/0 prefix with contiguous/spaced/dashed digits, or 10-digit starting with 6-9)
  {
    type: 'PHONE',
    regex: /(?:\+91[ -]?(?:0[ -]?)?|\b0[ -]?)[6-9]\d{4}[ -]?\d{5}\b|\b[6-9]\d{9}\b/g,
    confidence: 0.9,
  },
  // SSN (US)
  {
    type: 'SSN',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    confidence: 0.9,
  },
  // IBAN (International Bank Account Number with mod-97 verification)
  {
    type: 'IBAN',
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
    confidence: 0.95,
    validator: (m) => validateIban(m),
  },
  // IPv4 Address
  {
    type: 'IP_ADDRESS',
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    confidence: 0.85,
  },
  // Indian Court Case numbers (e.g., "CIVIL APPEAL NO. 1234 OF 2020", "WRIT PETITION (C) NO. 56 OF 2021")
  {
    type: 'CASE_ID',
    regex: /\b(?:CIVIL|CRIMINAL|WRIT|SPECIAL LEAVE|SLP|REVIEW|CONTEMPT|APPEAL|COMPANY)\s+(?:PETITION|APPEAL|SUIT|MISC\.?|NO\.?|NUMBER)\s+(?:\([A-Z]+\)\s+)?\d+\s+(?:OF|\/)\s+\d{4}\b/gi,
    confidence: 0.95,
  },
  // Short case citation: e.g. "case CRL123456", "appeal no. CA2021A"
  {
    type: 'CASE_ID',
    regex: /\b(?:case|appeal|petition|suit|citation|no\.?|number)\s+[A-Z]{2,5}\d{2,6}[A-Z]?\b/gi,
    confidence: 0.85,
  },
];

export interface DetectOptions {
  glossary?: string[];
  validateChecksums?: boolean;
  customDetectors?: CustomDetector[];
}

/**
 * Detect PII entities in input text.
 * Returns non-overlapping spans sorted by start index.
 */
export function detectPii(text: string, options?: DetectOptions | string[]): DetectedEntity[] {
  if (!text) return [];

  const opts: DetectOptions = Array.isArray(options)
    ? { glossary: options, validateChecksums: true }
    : { validateChecksums: true, ...options };

  const found: DetectedEntity[] = [];

  // Run built-in patterns
  for (const p of BUILTIN_PATTERNS) {
    p.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.regex.exec(text)) !== null) {
      const matchStr = m[0];
      if (opts.validateChecksums && p.validator && !p.validator(matchStr)) {
        continue;
      }
      found.push({
        type: p.type,
        start: m.index,
        end: m.index + matchStr.length,
        value: matchStr,
        confidence: p.confidence,
      });
    }
  }

  // Run custom detectors
  if (opts.customDetectors) {
    for (const cd of opts.customDetectors) {
      cd.regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = cd.regex.exec(text)) !== null) {
        const matchStr = m[0];
        if (cd.validator && !cd.validator(matchStr)) {
          continue;
        }
        found.push({
          type: cd.type,
          start: m.index,
          end: m.index + matchStr.length,
          value: matchStr,
          confidence: cd.confidence ?? 0.9,
        });
      }
    }
  }

  // Run glossary matches
  if (opts.glossary && opts.glossary.length > 0) {
    for (const term of opts.glossary) {
      if (!term || term.trim().length === 0) continue;
      const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const prefix = /^\w/.test(term) ? '\\b' : '(?<=^|\\s|[^\\w])';
      const suffix = /\w$/.test(term) ? '\\b' : '(?=\\s|[^\\w]|$)';
      const re = new RegExp(`${prefix}${escaped}${suffix}`, 'gi');
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        found.push({
          type: 'CUSTOM',
          start: m.index,
          end: m.index + m[0].length,
          value: m[0],
          confidence: 1.0,
        });
      }
    }
  }

  // Resolve overlaps: Prioritize higher confidence, then longer span length
  const candidates = [...found].sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    const lenA = a.end - a.start;
    const lenB = b.end - b.start;
    if (lenB !== lenA) return lenB - lenA;
    return a.start - b.start;
  });

  const selected: DetectedEntity[] = [];

  for (const candidate of candidates) {
    const hasOverlap = selected.some(
      (s) => candidate.start < s.end && candidate.end > s.start
    );
    if (!hasOverlap) {
      selected.push(candidate);
    }
  }

  // Final presentation order: sort by position in text ascending
  return selected.sort((a, b) => a.start - b.start);
}
