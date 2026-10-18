import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import type { RestoreReport } from './session.js';

/**
 * Value-free audit events. They record what Vela did to each request (route,
 * entity types and counts, actions, NER status, policy, restore counts) so a
 * compliance team can show the control operated. They never contain values,
 * hashes of values or placeholders.
 *
 * Each request produces a `vela.request` event before anything is sent
 * upstream and a `vela.response` event when the response is complete (or a
 * single `vela.blocked` / `vela.error` event).
 */
export interface AuditEvent {
  event: 'vela.request' | 'vela.response' | 'vela.blocked' | 'vela.error';
  request_id: string;
  ts: string;
  vela_version: string;
  method: string;
  route: string;
  /** Upstream host (no path or query). */
  upstream?: string;
  format?: string;
  model?: string;
  tenant?: string;
  /** 'stable' when a caller-supplied session id was used. */
  session?: 'random' | 'stable';
  policy_id?: string;
  policy_hash?: string;
  key_id?: string;
  /** NER (async recognizer) status for this request. */
  ner?: 'none' | 'ok' | 'failed_continued';
  /** Detected entities by type (occurrences). */
  entities?: Record<string, number>;
  /** Unique values by masking method. */
  actions?: Record<string, number>;
  /** Placeholders restored or kept per response field. */
  restore?: RestoreReport;
  status?: number;
  /** Class name of the error that stopped the request (never its message). */
  error_type?: string;
  latency_ms?: number;
  /** Set by hash-chaining sinks. */
  prev_hash?: string;
  hash?: string;
}

export type AuditSink = (event: AuditEvent) => void | Promise<void>;

export const newRequestId = (): string => randomUUID();

/** Pretty much everything an auditor needs, one JSON line per event on stdout. */
export function consoleSink(): AuditSink {
  return (e) => {
    process.stdout.write(JSON.stringify(e) + '\n');
  };
}

/** Canonical JSON (sorted keys) so the hash doesn't depend on property order. */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v as object)
      .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson((v as Record<string, unknown>)[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v);
}

const GENESIS = '0'.repeat(64);

function chainHash(prev: string, e: AuditEvent): string {
  const { hash: _h, ...rest } = e;
  return createHash('sha256').update(prev).update('\n').update(canonicalJson({ ...rest, prev_hash: prev })).digest('hex');
}

/**
 * Append events to a JSON-lines file. With `hashChain` (default), every event
 * carries the previous event's hash and its own, so deleting or editing a line
 * is detectable with `verifyAuditChain()`. Writes are synchronous so events
 * stay in order and a failed write fails the request.
 */
export function jsonlFileSink(path: string, opts: { hashChain?: boolean } = {}): AuditSink {
  const chain = opts.hashChain ?? true;
  let prev = GENESIS;
  if (chain && existsSync(path)) {
    const lines = readFileSync(path, 'utf8').trimEnd().split('\n').filter(Boolean);
    const last = lines.at(-1);
    if (last) prev = (JSON.parse(last) as AuditEvent).hash ?? GENESIS;
  }
  return (e) => {
    let out: AuditEvent = e;
    if (chain) {
      const hash = chainHash(prev, e);
      out = { ...e, prev_hash: prev, hash };
      prev = hash;
    }
    appendFileSync(path, JSON.stringify(out) + '\n', { mode: 0o600 });
  };
}

/** Check a hash-chained audit log. Returns the first line (1-based) that doesn't verify. */
export function verifyAuditChain(content: string): { ok: true; events: number } | { ok: false; line: number } {
  let prev = GENESIS;
  const lines = content.trimEnd().split('\n').filter(Boolean);
  for (let i = 0; i < lines.length; i++) {
    let e: AuditEvent;
    try {
      e = JSON.parse(lines[i] as string) as AuditEvent;
    } catch {
      return { ok: false, line: i + 1 };
    }
    const { prev_hash, hash, ...rest } = e;
    if (prev_hash !== prev || hash !== chainHash(prev, rest as AuditEvent)) return { ok: false, line: i + 1 };
    prev = hash;
  }
  return { ok: true, events: lines.length };
}
