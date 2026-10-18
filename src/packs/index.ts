/**
 * Opt-in detector packs for regulated data. Each pack is a list of
 * `DetectorPattern`s run alongside the built-in detectors; detected values
 * become placeholders (`[CARD_CVV_1]`) unless a policy says otherwise.
 *
 * Enable with `new Vela({ packs: ['pci', 'india-bfsi'] })` or a policy's
 * `packs` list. Most patterns need a context cue ("CVV", "UAN", "NHS") or
 * pass a checksum, to keep false positives low. Every pack has positive and
 * negative cases in `tests/corpus/packs/`.
 */
import type { DetectorPattern } from '../core/detector.js';
import { luhnCheckDigit } from '../core/algorithms/luhn.js';

const digits = (s: string): number[] => (s.match(/\d/g) ?? []).map(Number);

/** Luhn check for any length (the card validator only accepts 13-19 digits). */
function luhn(s: string): boolean {
  const d = s.replace(/\D/g, '');
  return d.length > 1 && luhnCheckDigit(d.slice(0, -1)) === Number(d.slice(-1));
}

/** ISO 7064 MOD 97-10 over an alphanumeric string (LEI). */
function mod97(s: string): number {
  let r = 0;
  for (const ch of s.toUpperCase()) {
    const v = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of v) r = (r * 10 + Number(d)) % 97;
  }
  return r;
}

/** ABA routing number: 3-7-1 weighted sum divisible by 10. */
function validAba(s: string): boolean {
  const d = digits(s);
  if (d.length !== 9) return false;
  const sum = [3, 7, 1, 3, 7, 1, 3, 7, 1].reduce((acc, w, i) => acc + w * (d[i] as number), 0);
  return sum % 10 === 0 && sum > 0;
}

/** NHS number: modulus 11 with weights 10..2. */
function validNhs(s: string): boolean {
  const d = digits(s);
  if (d.length !== 10) return false;
  const sum = d.slice(0, 9).reduce((acc, x, i) => acc + x * (10 - i), 0);
  const check = 11 - (sum % 11);
  return (check === 11 ? 0 : check) === d[9] && check !== 10;
}

/** Spanish DNI / NIE control letter. */
function validDni(s: string): boolean {
  const t = s.toUpperCase().replace(/[\s-]/g, '');
  const m = /^([XYZ]?)(\d{7,8})([A-Z])$/.exec(t);
  if (!m) return false;
  const prefix = ({ X: '0', Y: '1', Z: '2' } as Record<string, string>)[m[1] as string] ?? '';
  const num = Number(prefix + m[2]);
  return 'TRWAGMYFPDXBNJZSQVHLCKE'[num % 23] === m[3];
}

/** French NIR (social security number): key = 97 - (first 13 digits mod 97). Corsica 2A/2B. */
function validNir(s: string): boolean {
  const t = s.toUpperCase().replace(/\s/g, '');
  if (!/^[12]\d{4}(?:\d{2}|2A|2B)\d{8}$/.test(t)) return false;
  const body = t.slice(0, 13).replace('2A', '19').replace('2B', '18');
  const key = Number(t.slice(13));
  return 97 - Number(BigInt(body) % 97n) === key;
}

/** Singapore NRIC/FIN checksum (S, T, F, G prefixes). */
function validNric(s: string): boolean {
  const t = s.toUpperCase();
  const m = /^([STFG])(\d{7})([A-Z])$/.exec(t);
  if (!m) return false;
  const w = [2, 7, 6, 5, 4, 3, 2];
  let sum = (m[2] as string).split('').reduce((a, d, i) => a + Number(d) * (w[i] as number), 0);
  if (m[1] === 'T' || m[1] === 'G') sum += 4;
  const table = m[1] === 'S' || m[1] === 'T' ? 'JZIHGFEDCBA' : 'XWUTRQPNMLK';
  return table[sum % 11] === m[3];
}

/** Brazilian CPF check digits. */
function validCpf(s: string): boolean {
  const d = digits(s);
  if (d.length !== 11 || d.every((x) => x === d[0])) return false;
  const check = (n: number): number => {
    const sum = d.slice(0, n).reduce((a, x, i) => a + x * (n + 1 - i), 0);
    const r = (sum * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return check(9) === d[9] && check(10) === d[10];
}

const cue = (words: string, window = 40): DetectorPattern['context'] => ({
  require: new RegExp(`\\b(?:${words})\\b[^\\n]{0,${window - 10}}$`, 'i'),
  window,
});

const INDIAN_STATE_CODES =
  'AN|AP|AR|AS|BR|CG|CH|DD|DL|DN|GA|GJ|HP|HR|JH|JK|KA|KL|LA|LD|MH|ML|MN|MP|MZ|NL|OD|OR|PB|PY|RJ|SK|TG|TN|TR|TS|UK|UP|WB';

export const DETECTOR_PACKS: Record<string, DetectorPattern[]> = {
  /** PCI DSS sensitive authentication data and card expiry. */
  pci: [
    {
      type: 'CARD_CVV',
      regex: /(?<![\d-])\d{3,4}(?![\d-])/g,
      confidence: 0.97,
      context: { require: /\b(?:cvv2?|cvc2?|cid|csc|security code|card verification(?: value| code)?)\b[^\n\d]{0,15}$/i, window: 40 },
    },
    {
      type: 'CARD_EXPIRY',
      regex: /(?<![\d/])(?:0[1-9]|1[0-2])\s?\/\s?(?:\d{4}|\d{2})(?![\d/])/g,
      confidence: 0.92,
      context: { require: /\b(?:exp(?:iry|ires|iration)?(?: date)?|valid (?:thru|through|till|until)|mm\s?\/\s?yy)\b[^\n\d]{0,15}$/i, window: 40 },
    },
    {
      // Magnetic-stripe track 1 and track 2 data.
      type: 'CARD_TRACK_DATA',
      regex: /%B\d{13,19}\^[^^\n]{2,26}\^\d{7}[^\s?]{0,79}\??|;\d{13,19}=\d{7}[^\s?]{0,30}\??/g,
      confidence: 1,
    },
  ],

  /** Indian banking, securities, KYC and corporate identifiers. */
  'india-bfsi': [
    { type: 'CKYC_ID', regex: /(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{6}(?!\d)/g, confidence: 0.96, context: cue('ckyc|ckycr|kin|kyc identification number') },
    { type: 'UAN', regex: /(?<!\d)\d{12}(?!\d)/g, confidence: 0.96, context: cue('uan|universal account number|epf|pf account') },
    { type: 'DEMAT_ID', regex: /\bIN\d{14}\b/g, confidence: 0.95 },
    { type: 'DEMAT_ID', regex: /(?<!\d)\d{16}(?!\d)/g, confidence: 0.96, context: cue('demat|bo id|beneficiary owner|dp id|cdsl|client id') },
    { type: 'CIN', regex: /\b[LU]\d{5}[A-Z]{2}\d{4}(?:PLC|PTC|OPC|NPL|GOI|SGC|FLC|FTC|GAP|GAT|ULL|ULT)\d{6}\b/g, confidence: 0.97 },
    { type: 'DIN', regex: /(?<!\d)\d{8}(?!\d)/g, confidence: 0.95, context: cue('din|director identification number') },
    { type: 'TAN', regex: /\b[A-Z]{4}\d{5}[A-Z]\b/g, confidence: 0.95, context: cue('tan|tax deduction account') },
    {
      type: 'LEI',
      regex: /\b[A-Z0-9]{18}\d{2}\b/g,
      confidence: 0.94,
      validator: (m) => /[A-Z]/.test(m) && mod97(m) === 1,
      checksum: true,
    },
    { type: 'MICR', regex: /(?<!\d)\d{9}(?!\d)/g, confidence: 0.95, context: cue('micr') },
    { type: 'SWIFT_BIC', regex: /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g, confidence: 0.93, context: cue('swift|bic|swift code') },
    {
      type: 'VEHICLE_REG',
      regex: new RegExp(`\\b(?:(?:${INDIAN_STATE_CODES})[ -]?\\d{1,2}[ -]?[A-Z]{1,3}[ -]?\\d{4}|\\d{2}[ -]?BH[ -]?\\d{4}[ -]?[A-Z]{1,2})\\b`, 'g'),
      confidence: 0.9,
    },
  ],

  /** Indian health identifiers (ABDM) and hospital record numbers. */
  'health-in': [
    { type: 'ABHA_NUMBER', regex: /(?<![\d-])\d{2}-\d{4}-\d{4}-\d{4}(?![\d-])/g, confidence: 0.95 },
    { type: 'ABHA_NUMBER', regex: /(?<!\d)\d{14}(?!\d)/g, confidence: 0.96, context: cue('abha|health id|ndhm|abdm') },
    { type: 'ABHA_ADDRESS', regex: /\b[A-Za-z0-9._]{3,32}@(?:abdm|sbx|ndhm)\b/g, confidence: 0.98 },
    {
      type: 'MEDICAL_RECORD',
      regex: /\b[A-Z0-9][A-Z0-9/-]{3,18}[A-Z0-9]\b/gi,
      confidence: 0.9,
      context: { require: /\b(?:mrn|uhid|medical record(?: number| no\.?)?|patient id|hospital (?:no|number)|ip no|op no|reg(?:istration)? no)\b[^\n\w]{0,6}$/i, window: 40 },
      validator: (m) => /\d/.test(m),
    },
  ],

  /** United States identifiers beyond SSN. */
  us: [
    { type: 'US_ITIN', regex: /\b9\d{2}-(?:5\d|6[0-5]|7\d|8[0-8]|9[0-2]|9[4-9])-\d{4}\b/g, confidence: 0.96 },
    { type: 'US_EIN', regex: /\b\d{2}-\d{7}\b/g, confidence: 0.93, context: cue('ein|employer identification|fein|tax id') },
    { type: 'ABA_ROUTING', regex: /(?<!\d)\d{9}(?!\d)/g, confidence: 0.95, context: cue('routing|aba|rtn'), validator: validAba, checksum: true },
    {
      type: 'US_MBI',
      regex: /\b[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y]{2}\d{2}\b/g,
      confidence: 0.94,
    },
  ],

  /** UK and EU national identifiers. */
  'eu-uk': [
    {
      type: 'UK_NINO',
      regex: /\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g,
      confidence: 0.95,
    },
    { type: 'UK_NHS', regex: /(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{4}(?!\d)/g, confidence: 0.96, context: cue('nhs'), validator: validNhs, checksum: true },
    { type: 'ES_DNI', regex: /\b(?:\d{8}|[XYZ]\d{7})-?[A-Z]\b/g, confidence: 0.94, validator: validDni, checksum: true },
    { type: 'IT_FISCAL_CODE', regex: /\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b/g, confidence: 0.95 },
    { type: 'DE_TAX_ID', regex: /(?<!\d)\d{2} ?\d{3} ?\d{3} ?\d{3}(?!\d)/g, confidence: 0.95, context: cue('steuer-?id|steueridentifikationsnummer|idnr|tax id') },
    { type: 'FR_NIR', regex: /\b[12] ?\d{2} ?\d{2} ?(?:\d{2}|2A|2B) ?\d{3} ?\d{3} ?\d{2}\b/g, confidence: 0.95, validator: validNir, checksum: true },
  ],

  /** Other national identifiers common in cross-border work. */
  intl: [
    { type: 'SG_NRIC', regex: /\b[STFG]\d{7}[A-Z]\b/g, confidence: 0.95, validator: validNric, checksum: true },
    { type: 'AE_EMIRATES_ID', regex: /\b784-?\d{4}-?\d{7}-?\d\b/g, confidence: 0.96, validator: luhn, checksum: true },
    { type: 'BR_CPF', regex: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g, confidence: 0.94, validator: validCpf, checksum: true },
    { type: 'CA_SIN', regex: /(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{3}(?!\d)/g, confidence: 0.95, context: cue('sin|social insurance'), validator: luhn, checksum: true },
    { type: 'AU_TFN', regex: /(?<!\d)\d{3} ?\d{3} ?\d{2,3}(?!\d)/g, confidence: 0.95, context: cue('tfn|tax file number') },
  ],
};

/** Resolve pack names to patterns. Unknown names are an error (a typo must not silently disable a pack). */
export function resolvePacks(names: string[]): DetectorPattern[] {
  return names.flatMap((n) => {
    const p = DETECTOR_PACKS[n];
    if (!p) throw new Error(`Unknown detector pack "${n}". Available: ${Object.keys(DETECTOR_PACKS).join(', ')}`);
    return p;
  });
}
