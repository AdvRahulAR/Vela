import type { EntityType } from '../types.js';

export const DEFAULT_FPE_TYPES: EntityType[] = [
  'AADHAAR',
  'PAN',
  'GSTIN',
  'CREDIT_CARD',
  'PHONE',
  'SSN',
  'IBAN',
  'IP_ADDRESS',
  'CASE_ID',
];

export const DEFAULT_TOKEN_TYPES: EntityType[] = [
  'EMAIL',
  'PERSON',
  'LOCATION',
  'ORG',
  'SECRET_KEY',
  'JWT',
  'CUSTOM',
];

export const PACKAGE_VERSION = '0.2.1';

export const DIGITS = '0123456789';
export const UPPER_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
export const LOWER_ALNUM = 'abcdefghijklmnopqrstuvwxyz0123456789';
export const MIXED_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export const DEFAULT_TWEAK = new Uint8Array(8);

export const DEFAULT_PROXY_PORT = 8787;
export const DEFAULT_UPSTREAM_URL = 'https://api.openai.com';

export const LLM_REQUEST_PATHS = [
  '/chat/completions',
  '/v1/chat/completions',
  '/v1/messages',
  '/v1/responses',
];
