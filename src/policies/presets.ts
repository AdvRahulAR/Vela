import { existsSync } from 'node:fs';
import { loadPolicy, validatePolicy, type VelaPolicy } from '../core/policy.js';

/**
 * Starting points for common compliance regimes. Copy one into a policy file
 * and adapt it; your compliance team owns the final choices. None of them makes
 * Vela a de-identification tool: masking is reversible and detection is not
 * complete (see docs/THREAT_MODEL.md).
 */
export const POLICY_PRESETS: Record<string, VelaPolicy> = {
  'dpdp-baseline': {
    id: 'dpdp-baseline',
    version: 1,
    description: 'India DPDP Act baseline: mask personal data, never send secrets, synthetic-safe Aadhaar, tool calls keep placeholders.',
    entities: { SECRET_KEY: 'block', JWT: 'block', AADHAAR: 'fpe-synthetic' },
    restore: { toolArguments: 'placeholders' },
  },
  'india-bfsi': {
    id: 'india-bfsi',
    version: 1,
    description: 'Indian banks, NBFCs, brokers and insurers: card data and secrets never leave, KYC and securities identifiers masked, no images or files.',
    packs: ['pci', 'india-bfsi'],
    entities: {
      CREDIT_CARD: 'block',
      CARD_CVV: 'block',
      CARD_TRACK_DATA: 'block',
      CARD_EXPIRY: 'redact',
      SECRET_KEY: 'block',
      JWT: 'block',
      AADHAAR: 'fpe-synthetic',
      DATE_OF_BIRTH: 'redact',
    },
    nonText: 'block',
    restore: { toolArguments: 'placeholders' },
  },
  pci: {
    id: 'pci',
    version: 1,
    description: 'PCI DSS: card numbers become synthetic (Luhn-invalid) ciphertext, sensitive authentication data is blocked.',
    packs: ['pci'],
    entities: { CREDIT_CARD: 'fpe-synthetic', CARD_CVV: 'block', CARD_TRACK_DATA: 'block', CARD_EXPIRY: 'redact', SECRET_KEY: 'block' },
    nonText: 'block',
    restore: { toolArguments: 'placeholders' },
  },
  'hipaa-safe-harbor': {
    id: 'hipaa-safe-harbor',
    version: 1,
    description: 'Covers more HIPAA Safe Harbor identifiers (record numbers, US IDs, dates of birth). A safeguard, not de-identification.',
    packs: ['us', 'health-in'],
    entities: { DATE_OF_BIRTH: 'redact', SECRET_KEY: 'block', JWT: 'block' },
    nonText: 'block',
    restore: { toolArguments: 'placeholders' },
  },
  'gdpr-pseudonymise': {
    id: 'gdpr-pseudonymise',
    version: 1,
    description: 'GDPR pseudonymisation (Art. 4(5)): EU/UK national identifiers masked, secrets blocked, tool calls keep placeholders.',
    packs: ['eu-uk', 'intl'],
    entities: { SECRET_KEY: 'block', JWT: 'block' },
    restore: { toolArguments: 'placeholders' },
  },
};

/** A preset by name, or a policy file (.json / .yaml / .yml) by path. */
export function resolvePolicy(nameOrPath: string): VelaPolicy {
  const preset = POLICY_PRESETS[nameOrPath];
  if (preset) return validatePolicy(preset);
  if (!existsSync(nameOrPath)) {
    throw new Error(`No policy preset or file "${nameOrPath}". Presets: ${Object.keys(POLICY_PRESETS).join(', ')}`);
  }
  return loadPolicy(nameOrPath);
}
