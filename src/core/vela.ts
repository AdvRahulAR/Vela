import { randomBytes } from 'node:crypto';
import { DEFAULT_FPE_TYPES, DEFAULT_TOKEN_TYPES, STANDARD_ENTITY_TYPES } from '../config/constants.js';

/** Types the bundled Presidio adapter can return with its default type map. */
const PRESIDIO_TYPES = ['NRP'];
import { FpeMasker } from './fpe.js';
import { MaskSession, type SessionEngine } from './session.js';
import { Restorer, replacementsFrom, type RestoreOptions, type StreamRestorer } from './matcher.js';
import { Logger } from '../utils/logger.js';
import type { AuditEvent, AuditSink } from './audit.js';
import type { KeyProvider } from './keys.js';
import { resolvePacks } from '../packs/index.js';
import { VelaPolicyError, policyHash, validatePolicy, type VelaPolicy } from './policy.js';
import type { MaskResult, SessionOptions, UnmaskResult, VelaConfig } from '../types.js';

/**
 * Vela — LLM privacy gateway core.
 *
 * Structured identifiers are replaced with NIST FF1 format-preserving
 * ciphertexts that stay structurally valid (checksums recomputed); everything
 * else (emails, names, addresses, secrets…) becomes a reversible placeholder
 * such as `[PERSON_1]`. Values that cannot be format-preserved safely always
 * fall back to a placeholder — nothing detected is ever passed through.
 */
export class Vela {
  private readonly engine: SessionEngine;
  private readonly logger: Logger;
  /** Where the integrations send audit events (`VelaConfig.audit`). */
  readonly audit: AuditSink | undefined;
  /** Static fields copied into every audit event (policy id and hash, key id). */
  readonly auditContext: { policy_id?: string; policy_hash?: string; key_id?: string };

  private readonly observers: Array<(e: AuditEvent) => void> = [];

  /**
   * Observe audit events (for metrics). Observers see every event even
   * without an audit sink; an observer that throws is ignored.
   */
  onEvent(fn: (e: AuditEvent) => void): void {
    this.observers.push(fn);
  }

  /** @internal Deliver an event to observers. */
  notify(e: AuditEvent): void {
    for (const fn of this.observers) {
      try {
        fn(e);
      } catch {
        // Observers must not affect requests.
      }
    }
  }

  /**
   * Readiness: with async recognizers configured, run them once on a probe
   * text. 'failed' means requests would currently be blocked (or fall back,
   * with recognizerFailure 'continue').
   */
  async checkReady(): Promise<{ ready: boolean; ner: 'none' | 'ok' | 'failed' }> {
    if (!this.engine.asyncRecognizers.length) return { ready: true, ner: 'none' };
    const s = this.createSession();
    try {
      await s.prepare(['Readiness probe for the NER service']);
    } catch {
      return { ready: false, ner: 'failed' };
    }
    return s.nerStatus === 'failed_continued' ? { ready: true, ner: 'failed' } : { ready: true, ner: 'ok' };
  }

  /** The validated policy, if one was configured. */
  readonly policy: VelaPolicy | undefined;

  constructor(config: VelaConfig = {}) {
    const policy = config.policy ? validatePolicy(config.policy) : undefined;
    if (policy?.ner?.required) {
      if (!config.asyncRecognizers?.length) throw new VelaPolicyError(`policy "${policy.id}" requires an NER service (asyncRecognizers)`);
      if (config.recognizerFailure === 'continue') throw new VelaPolicyError(`policy "${policy.id}" requires recognizerFailure: 'block'`);
    }
    this.policy = policy;
    const packs = resolvePacks([...new Set([...(config.packs ?? []), ...(policy?.packs ?? [])])]);
    if (policy?.entities) {
      // A typo ("CREDITCARD: block") must not silently disable a rule: every type must be one
      // Vela or a configured detector can produce.
      const known = new Set<string>([
        ...STANDARD_ENTITY_TYPES,
        ...packs.map((p) => String(p.type)),
        ...(config.customDetectors ?? []).map((d) => String(d.type)),
        ...PRESIDIO_TYPES,
        ...(config.extraEntityTypes ?? []),
      ]);
      const unknown = Object.keys(policy.entities).filter((t) => !known.has(t));
      if (unknown.length) {
        throw new VelaPolicyError(
          `policy "${policy.id}" names unknown entity type(s) ${unknown.join(', ')}. Enable the detector pack that produces them, or declare types from your own recognizers in extraEntityTypes`,
        );
      }
    }
    // No key supplied: masking only needs a secret, random key — the maps kept
    // in each session are what restore values, not decryption.
    const key = config.fpeKey ?? new Uint8Array(randomBytes(32));
    this.engine = {
      fpe: new FpeMasker(key, config.fpeTweak),
      fpeTypes: config.fpeTypes ?? DEFAULT_FPE_TYPES,
      tokenTypes: config.tokenTypes ?? DEFAULT_TOKEN_TYPES,
      detect: {
        glossary: config.glossary ?? [],
        validateChecksums: config.validateChecksums ?? true,
        customDetectors: config.customDetectors ?? [],
        recognizers: config.recognizers ?? [],
        detectNames: config.detectNames ?? true,
        maskCitationParties: config.maskCitationParties ?? false,
        packs,
      },
      maxInputChars: config.maxInputChars ?? 2_000_000,
      asyncRecognizers: config.asyncRecognizers ?? [],
      recognizerFailure: config.recognizerFailure ?? 'block',
      recognizerTimeoutMs: config.recognizerTimeoutMs ?? 5000,
      ...(config.restore ?? policy?.restore ? { restore: { ...policy?.restore, ...config.restore } } : {}),
      ...(policy?.entities ? { actions: policy.entities, policyId: policy.id } : {}),
      onRecognizerFailure: (err) =>
        this.logger.warn('recognizer_failed_continuing', { error: err instanceof Error ? err.message : String(err) }),
    };
    this.logger = new Logger('vela-core', config.enableLogging ?? false);
    this.audit = config.audit;
    this.auditContext = {
      ...(policy ? { policy_id: policy.id, policy_hash: policyHash(policy) } : {}),
      ...(config.keyId ? { key_id: config.keyId } : {}),
    };
  }

  /**
   * Create a Vela whose FF1 key comes from a key provider (KMS, Vault,
   * environment). The provider's key id is recorded in audit events.
   *
   *   const vela = await Vela.create({ keyProvider: awsKmsKeyProvider({ … }), audit: jsonlFileSink('audit.jsonl') });
   */
  static async create(config: VelaConfig & { keyProvider: KeyProvider }): Promise<Vela> {
    const { keyProvider, ...rest } = config;
    const { key, keyId } = await keyProvider.getKey();
    return new Vela({ ...rest, fpeKey: key, keyId: rest.keyId ?? keyId });
  }

  /**
   * Start a masking session. Use one session per request (default) or pass a
   * stable `sessionId` per conversation to keep masked values identical across
   * turns (needed for provider prompt caching and server-side conversation state).
   */
  createSession(opts?: SessionOptions): MaskSession {
    return new MaskSession(this.engine, opts);
  }

  /**
   * Mask PII in text. Pass a session to mask several texts consistently;
   * without one, a fresh session is used for this call.
   */
  mask(text: string, session?: MaskSession): MaskResult {
    const start = Date.now();
    const s = session ?? this.createSession();
    const masked = s.mask(text);
    const result = s.toResult(masked);
    this.logger.info(
      'mask',
      {
        entitiesDetected: result.entities.length,
        fpeCount: Object.keys(result.fpeMap).length,
        tokenCount: Object.keys(result.mapping).length,
      },
      Date.now() - start,
    );
    return result;
  }

  /**
   * Like mask(), but first runs any configured async recognizers (NER
   * services). Works with or without `asyncRecognizers`.
   */
  async maskAsync(text: string, session?: MaskSession): Promise<MaskResult> {
    const s = session ?? this.createSession();
    await s.prepare([text]);
    return this.mask(text, s);
  }

  /** Restore original values in an LLM response. */
  unmask(text: string, source: MaskResult | MaskResult[] | MaskSession, opts?: RestoreOptions): UnmaskResult {
    const start = Date.now();
    const r =
      source instanceof MaskSession ? source.unmask(text, opts) : new Restorer(replacementsFrom(source)).restore(text, opts);
    this.logger.info('unmask', { restored: r.restored }, Date.now() - start);
    return r;
  }

  /** Create a streaming de-masker (chunk-boundary aware). */
  createStreamDeMasker(source: MaskResult | MaskResult[] | MaskSession, opts?: RestoreOptions): StreamRestorer {
    if (source instanceof MaskSession) return source.createStreamDeMasker(opts);
    return new Restorer(replacementsFrom(source)).createStream(opts);
  }
}
