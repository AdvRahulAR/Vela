/**
 * Generate a synthetic, labelled detection corpus (tests/corpus/generated/).
 * Deterministic (seeded), so the file is reproducible:
 *   npm run gen-corpus             # writes tests/corpus/generated/synthetic.jsonl
 *
 * Every value is synthetic. Identifiers carry valid checksums, so they are
 * detectable, but they are random and not taken from real people. Labels are
 * the spans the template inserted; the evaluation counts anything else as a
 * false positive. Templates deliberately include cases Vela is known to miss
 * (Indic scripts, bare first names, free-form addresses) so the report shows
 * real recall rather than a flattering number.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { generateVerhoeffChecksum } from '../src/core/algorithms/verhoeff.js';
import { luhnCheckDigit } from '../src/core/algorithms/luhn.js';
import { gstinCheckChar } from '../src/core/algorithms/gstin.js';

const SEED = 20261018;
const CASES = 1600;

let state = SEED;
function rand(): number {
  // mulberry32
  state = (state + 0x6d2b79f5) | 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const int = (n: number): number => Math.floor(rand() * n);
const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)] as T;
const digits = (n: number): string => Array.from({ length: n }, () => int(10)).join('');
const letters = (n: number): string => Array.from({ length: n }, () => String.fromCharCode(65 + int(26))).join('');

const FIRST = ['Rahul', 'Priya', 'Anil', 'Deepa', 'Arjun', 'Kavya', 'Suresh', 'Lakshmi', 'Vikram', 'Neha', 'Joseph', 'Mary', 'Mohammed', 'Fatima', 'Harpreet', 'Gurpreet', 'Sanjay', 'Anjali', 'Ravi', 'Meera', 'Thomas', 'Anitha', 'Rajesh', 'Pooja', 'Kiran', 'Sneha', 'Arun', 'Divya', 'Manoj', 'Shalini', 'Emma', 'James', 'Olivia', 'Daniel'];
const LAST = ['Sharma', 'Menon', 'Nair', 'Iyer', 'Reddy', 'Patel', 'Gupta', 'Singh', 'Khan', 'Fernandes', 'Mathew', 'Pillai', 'Rao', 'Das', 'Banerjee', 'Kulkarni', 'Joshi', 'Verma', 'Thomas', 'Kurian', 'Smith', 'Johnson', 'Williams'];
const INDIC = ['राहुल शर्मा', 'प्रिया वर्मा', 'അനിൽ മേനോൻ', 'ദീപ നായർ', 'அருண் ராஜ்', 'ಕಾವ್ಯ ರಾವ್', 'সুমন দাস'];
const CITIES: Array<[string, string]> = [['Kochi', '682016'], ['Bengaluru', '560001'], ['Pune', '411001'], ['Chennai', '600002'], ['Mumbai', '400001'], ['New Delhi', '110001'], ['Hyderabad', '500001'], ['Kolkata', '700016']];
const STREETS = ['MG Road', 'Park Street', 'Gandhi Nagar', 'Anna Salai', 'Linking Road', 'Residency Road', 'Banjara Hills Road', 'Marine Drive'];
const ORGS = ['Acme Technologies Pvt Ltd', 'Sunrise Textiles Private Limited', 'Bluewave Logistics LLP', 'Greenleaf Foods Ltd', 'Northstar Analytics Inc'];
const BANKS = ['HDFC', 'ICIC', 'SBIN', 'UTIB', 'KKBK', 'FDRL'];
const UPI = ['okaxis', 'okhdfcbank', 'oksbi', 'ybl', 'paytm'];
const DOMAINS = ['example.com', 'mailbox.in', 'corp.example.org'];

type E = { type: string; value: string };
type Case = { text: string; entities: E[]; tags: string[] };

const name = (): string => `${pick(FIRST)} ${pick(LAST)}`;
function aadhaar(): string {
  const p = String(2 + int(8)) + digits(10);
  const v = p + generateVerhoeffChecksum(p);
  return pick([`${v.slice(0, 4)} ${v.slice(4, 8)} ${v.slice(8)}`, v, `${v.slice(0, 4)}-${v.slice(4, 8)}-${v.slice(8)}`]);
}
const pan = (): string => letters(3) + pick(['P', 'C', 'H', 'F', 'A', 'T']) + letters(1) + digits(4) + letters(1);
function gstin(): string {
  const body = String(10 + int(27)).padStart(2, '0') + pan() + String(1 + int(9)) + 'Z';
  return body + gstinCheckChar(body);
}
function card(): string {
  const prefix = pick(['4', '51', '52', '53', '54', '55', '60', '65']);
  const p = prefix + digits(15 - prefix.length);
  const c = p + luhnCheckDigit(p);
  return pick([c, c.replace(/(\d{4})(?=\d)/g, '$1 '), c.replace(/(\d{4})(?=\d)/g, '$1-')]);
}
function iban(): string {
  const bban = letters(4) + digits(14);
  const num = (bban + 'GB00').replace(/[A-Z]/g, (ch) => String(ch.charCodeAt(0) - 55));
  let r = 0;
  for (const d of num) r = (r * 10 + Number(d)) % 97;
  const check = String(98 - r).padStart(2, '0');
  return `GB${check}${bban}`;
}
const phone = (): string => {
  const n = String(6 + int(4)) + digits(9);
  return pick([`+91 ${n.slice(0, 5)} ${n.slice(5)}`, `+91-${n}`, n, `0${n}`]);
};
const emailFor = (nm: string): string => `${nm.toLowerCase().replace(/\s+/g, pick(['.', '_', '']))}${int(100)}@${pick(DOMAINS)}`;
const upiFor = (nm: string): string => `${nm.split(' ')[0]?.toLowerCase()}${int(1000)}@${pick(UPI)}`;
const ifsc = (): string => `${pick(BANKS)}0${digits(6)}`;
const account = (): string => digits(9 + int(8));
const dob = (): string => `${String(1 + int(28)).padStart(2, '0')}/${String(1 + int(12)).padStart(2, '0')}/${1950 + int(55)}`;
const address = (): string => {
  const [city, pin] = pick(CITIES);
  return `${1 + int(200)}, ${pick(STREETS)}, ${city} ${pin}`;
};

/** Build a case from template parts: strings are literal text, [type, value] pairs are labelled entities. */
function build(tags: string[], ...parts: Array<string | [string, string]>): Case {
  let text = '';
  const entities: E[] = [];
  for (const p of parts) {
    if (typeof p === 'string') text += p;
    else {
      entities.push({ type: p[0], value: p[1] });
      text += p[1];
    }
  }
  return { text, entities, tags };
}

const TEMPLATES: Array<() => Case> = [
  () => {
    const n = name();
    return build(['kyc'], 'Customer: ', ['PERSON', n], ', PAN ', ['PAN', pan()], ', Aadhaar ', ['AADHAAR', aadhaar()], ', mobile ', ['PHONE', phone()], ', email ', ['EMAIL', emailFor(n)]);
  },
  () => {
    const n = name();
    return build(['bank'], 'Transfer by ', ['PERSON', n], ' from a/c ', ['BANK_ACCOUNT', account()], ' (IFSC ', ['IFSC', ifsc()], ') to UPI ', ['UPI_ID', upiFor(n)], '.');
  },
  () => build(['card'], 'Please charge card ', ['CREDIT_CARD', card()], ' for the renewal of ', ['PERSON', name()], '.'),
  () => build(['gst'], 'Invoice from ', ['ORG', pick(ORGS)], ', GSTIN ', ['GSTIN', gstin()], ', payable within 30 days.'),
  () => build(['iban'], 'Wire the refund to IBAN ', ['IBAN', iban()], ' today.'),
  () => build(['legal', 'address'], 'The petitioner ', ['PERSON', name()], ', residing at ', ['ADDRESS', address()], ', has filed this writ petition.'),
  () => build(['medical'], 'Patient ', ['PERSON', name()], ', DOB ', ['DATE_OF_BIRTH', dob()], ', was admitted with fever.'),
  () => {
    const f = pick(FIRST);
    return build(['hinglish', 'first-name'], 'bhai ', ['PERSON', f], ' ka number ', ['PHONE', phone()], ' hai, usko mail kar do');
  },
  () => build(['indic', 'name'], ['PERSON', pick(INDIC)], ' ने ₹5,000 का भुगतान किया'),
  () => {
    const n = name();
    return build(['chat', 'signoff'], 'Thanks for the update, will review tomorrow.\nRegards,\n', ['PERSON', n]);
  },
  () => build(['email'], 'Reach me at ', ['EMAIL', emailFor(name())], ' or on ', ['PHONE', phone()], '.'),
  () => build(['secret'], 'Rotate the key ', ['SECRET_KEY', `sk-proj-${letters(8)}${digits(8)}${letters(8)}`], ' after the incident.'),
  () => build(['ip'], 'Login from ', ['IP_ADDRESS', `${10 + int(200)}.${int(256)}.${int(256)}.${1 + int(254)}`], ' was flagged.'),
  // Negatives: no personal data, numbers that look like identifiers.
  () => build(['negative'], `Order ${digits(10)} shipped on ${1 + int(28)} March; invoice ${digits(8)} attached.`),
  () => build(['negative'], `Upgraded the service to version ${int(5)}.${int(10)}.${int(10)}.${int(100)} and restarted ${int(9) + 2} pods.`),
  () => build(['negative'], `Revenue grew ${int(40)}% to ₹${digits(4)} crore in FY${24 + int(3)}; margins held at ${int(30)}%.`),
  () => build(['negative'], `Please review the attached draft and share comments by Friday.`),
];

const cases: Case[] = [];
for (let i = 0; i < CASES; i++) cases.push(pick(TEMPLATES)());

const dir = join(__dirname, '..', 'tests', 'corpus', 'generated');
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, 'synthetic.jsonl'), cases.map((c) => JSON.stringify(c)).join('\n') + '\n');
const n = cases.reduce((a, c) => a + c.entities.length, 0);
console.log(`Wrote ${cases.length} cases, ${n} labelled entities (seed ${SEED})`);
