import type { EntityType, StandardEntityType } from '../types.js';

export const DEFAULT_FPE_TYPES: EntityType[] = [
  'AADHAAR',
  'PAN',
  'GSTIN',
  'CREDIT_CARD',
  'PHONE',
  'SSN',
  'IBAN',
  'IP_ADDRESS',
  'BANK_ACCOUNT',
  'IFSC',
  'PASSPORT',
];

export const DEFAULT_TOKEN_TYPES: EntityType[] = [
  'EMAIL',
  'UPI_ID',
  'VOTER_ID',
  'DRIVING_LICENCE',
  'PERSON',
  'ADDRESS',
  'DATE_OF_BIRTH',
  'PIN_CODE',
  'LOCATION',
  'ORG',
  'SECRET_KEY',
  'JWT',
  'MAC_ADDRESS',
  'CUSTOM',
];

/** Every built-in entity type. Any other type comes from a custom detector or recognizer. */
export const STANDARD_ENTITY_TYPES: ReadonlySet<EntityType> = new Set<StandardEntityType>([
  'AADHAAR', 'PAN', 'GSTIN', 'CREDIT_CARD', 'EMAIL', 'PHONE', 'SSN', 'IBAN', 'IP_ADDRESS', 'BANK_ACCOUNT',
  'IFSC', 'PASSPORT', 'VOTER_ID', 'DRIVING_LICENCE', 'UPI_ID', 'DATE_OF_BIRTH', 'PIN_CODE', 'ADDRESS',
  'SECRET_KEY', 'JWT', 'MAC_ADDRESS', 'PERSON', 'LOCATION', 'ORG', 'CUSTOM',
]);

export const PACKAGE_VERSION = '0.3.3';

export const DIGITS = '0123456789';
export const UPPER_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
export const LOWER_ALNUM = 'abcdefghijklmnopqrstuvwxyz0123456789';
export const MIXED_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export const DEFAULT_TWEAK = new Uint8Array(8);

export const DEFAULT_PROXY_PORT = 8787;
export const DEFAULT_PROXY_HOST = '127.0.0.1';
export const SESSION_HEADER = 'x-vela-session';
export const DEFAULT_UPSTREAM_URL = 'https://api.openai.com';
export const DEFAULT_ANTHROPIC_URL = 'https://api.anthropic.com';

export const LLM_REQUEST_PATHS = [
  '/chat/completions',
  '/v1/chat/completions',
  '/v1/messages',
  '/v1/responses',
];
