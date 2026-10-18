import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { createHash } from 'node:crypto';
import { canonicalJson } from './audit.js';
import type { RestorePolicy } from './session.js';
import type { EntityType } from '../types.js';

/**
 * What happens to a detected entity:
 * - `fpe`: format-preserving encryption (falls back to a placeholder if impossible);
 * - `fpe-synthetic`: FPE with a deliberately invalid check character, so the output
 *   can't be a real identifier (Aadhaar, card, GSTIN, IBAN; other types get a placeholder);
 * - `token`: reversible placeholder such as `[EMAIL_1]`;
 * - `redact`: placeholder that is never restored;
 * - `block`: reject the whole request (HTTP 422) and send nothing;
 * - `allow`: leave the value in clear text.
 */
export type EntityAction = 'fpe' | 'fpe-synthetic' | 'token' | 'redact' | 'block' | 'allow';

export const ENTITY_ACTIONS: readonly EntityAction[] = ['fpe', 'fpe-synthetic', 'token', 'redact', 'block', 'allow'];

/**
 * A versioned, declarative masking policy. Load it from JSON or YAML with
 * `loadPolicy()`, or use a preset (`POLICY_PRESETS`). Its hash goes into every
 * audit event, so an auditor can tell which policy handled a request.
 */
export interface VelaPolicy {
  /** Short identifier, recorded in audit events. */
  id: string;
  version?: string | number;
  description?: string;
  /** Per entity type. Types not listed keep Vela's default (FPE for structured IDs, placeholder otherwise). */
  entities?: Record<string, EntityAction>;
  /** Upstream hosts requests may go to (globs such as `*.openai.azure.com`). Others are rejected (403). */
  providers?: { allow: string[] };
  /** Models requests may name (globs such as `gpt-4.1*`). Others are rejected (403). */
  models?: { allow: string[] };
  /** Images, audio, files and other non-text content: `block` rejects the request (422). Default `allow`. */
  nonText?: 'allow' | 'block';
  /** Which response fields get placeholders restored. */
  restore?: RestorePolicy;
  /** `required: true`: Vela refuses to start without an NER service, and a failing one blocks requests. */
  ner?: { required: boolean };
  /** Detector packs to enable (see `DETECTOR_PACKS`). */
  packs?: string[];
}

export class VelaPolicyError extends Error {
  constructor(message: string) {
    super(`Invalid Vela policy: ${message}`);
    this.name = 'VelaPolicyError';
  }
}

const TOP_KEYS = new Set(['id', 'version', 'description', 'entities', 'providers', 'models', 'nonText', 'restore', 'ner', 'packs']);
const RESTORE_KEYS = new Set(['content', 'toolArguments', 'thinking']);

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function stringList(v: unknown, where: string): string[] {
  if (!Array.isArray(v) || v.some((x) => typeof x !== 'string' || !x)) throw new VelaPolicyError(`${where} must be a list of strings`);
  return v as string[];
}

/**
 * Check a parsed policy. Unknown keys and unknown actions are errors, not
 * ignored: a typo must not silently weaken the policy. `entities` values may
 * be an action string or `{ action }`.
 */
export function validatePolicy(input: unknown): VelaPolicy {
  if (!isObj(input)) throw new VelaPolicyError('expected an object');
  for (const k of Object.keys(input)) if (!TOP_KEYS.has(k)) throw new VelaPolicyError(`unknown key "${k}"`);
  if (typeof input.id !== 'string' || !/^[\w.-]{1,64}$/.test(input.id)) throw new VelaPolicyError('"id" must be 1-64 letters, digits, ".", "_" or "-"');
  const out: VelaPolicy = { id: input.id };
  if (input.version !== undefined) {
    if (typeof input.version !== 'string' && typeof input.version !== 'number') throw new VelaPolicyError('"version" must be a string or number');
    out.version = input.version;
  }
  if (input.description !== undefined) {
    if (typeof input.description !== 'string') throw new VelaPolicyError('"description" must be a string');
    out.description = input.description;
  }
  if (input.entities !== undefined) {
    if (!isObj(input.entities)) throw new VelaPolicyError('"entities" must be a map of entity type to action');
    const entities: Record<string, EntityAction> = {};
    for (const [type, raw] of Object.entries(input.entities)) {
      const action = isObj(raw) ? raw.action : raw;
      if (isObj(raw) && Object.keys(raw).some((k) => k !== 'action')) throw new VelaPolicyError(`entities.${type} only takes "action"`);
      if (!/^[A-Z][A-Z0-9_]*$/.test(type)) throw new VelaPolicyError(`entity type "${type}" must be UPPER_SNAKE_CASE`);
      if (typeof action !== 'string' || !ENTITY_ACTIONS.includes(action as EntityAction)) {
        throw new VelaPolicyError(`entities.${type}: action must be one of ${ENTITY_ACTIONS.join(', ')}`);
      }
      entities[type] = action as EntityAction;
    }
    out.entities = entities;
  }
  for (const key of ['providers', 'models'] as const) {
    const v = input[key];
    if (v === undefined) continue;
    if (!isObj(v) || Object.keys(v).some((k) => k !== 'allow')) throw new VelaPolicyError(`"${key}" takes only "allow"`);
    out[key] = { allow: stringList(v.allow, `${key}.allow`) };
  }
  if (input.nonText !== undefined) {
    if (input.nonText !== 'allow' && input.nonText !== 'block') throw new VelaPolicyError('"nonText" must be allow or block');
    out.nonText = input.nonText;
  }
  if (input.restore !== undefined) {
    if (!isObj(input.restore)) throw new VelaPolicyError('"restore" must be an object');
    const restore: RestorePolicy = {};
    for (const [k, v] of Object.entries(input.restore)) {
      if (!RESTORE_KEYS.has(k)) throw new VelaPolicyError(`unknown key "restore.${k}"`);
      if (v !== 'restore' && v !== 'placeholders') throw new VelaPolicyError(`restore.${k} must be restore or placeholders`);
      restore[k as keyof RestorePolicy] = v;
    }
    out.restore = restore;
  }
  if (input.ner !== undefined) {
    if (!isObj(input.ner) || typeof input.ner.required !== 'boolean' || Object.keys(input.ner).length !== 1) {
      throw new VelaPolicyError('"ner" must be { required: true|false }');
    }
    out.ner = { required: input.ner.required };
  }
  if (input.packs !== undefined) out.packs = stringList(input.packs, 'packs');
  return out;
}

/** Read a policy from a `.json`, `.yaml` or `.yml` file and validate it. */
export function loadPolicy(path: string): VelaPolicy {
  const text = readFileSync(path, 'utf8');
  let parsed: unknown;
  try {
    if (/\.ya?ml$/i.test(path)) {
      parsed = parseYaml(text, { uniqueKeys: true });
    } else {
      parsed = JSON.parse(text);
    }
  } catch (err) {
    throw new VelaPolicyError(`could not parse ${path}: ${err instanceof Error ? err.message : String(err)}`);
  }
  return validatePolicy(parsed);
}

/** SHA-256 of the policy's canonical JSON: the same policy hashes the same in YAML or JSON. */
export function policyHash(policy: VelaPolicy): string {
  return 'sha256:' + createHash('sha256').update(canonicalJson(policy)).digest('hex');
}

/** Glob with `*` wildcards, case-insensitive, whole string. */
export function globMatch(pattern: string, value: string): boolean {
  const re = new RegExp('^' + pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$', 'i');
  return re.test(value);
}

/** Resolved action for a type, or undefined for "Vela's default". */
export function actionFor(policy: VelaPolicy | undefined, type: EntityType): EntityAction | undefined {
  return policy?.entities?.[type];
}
