import { randomBytes } from 'node:crypto';
import { DEFAULT_FPE_TYPES, DEFAULT_TOKEN_TYPES } from '../config/constants.js';
import { FpeMasker } from './fpe.js';
import { MaskSession, type SessionEngine } from './session.js';
import { Restorer, replacementsFrom, type RestoreOptions, type StreamRestorer } from './matcher.js';
import { Logger } from '../utils/logger.js';
import type { AuditSink } from './audit.js';
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

  constructor(config: VelaConfig = {}) {
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
      },
      maxInputChars: config.maxInputChars ?? 2_000_000,
      asyncRecognizers: config.asyncRecognizers ?? [],
      recognizerFailure: config.recognizerFailure ?? 'block',
      recognizerTimeoutMs: config.recognizerTimeoutMs ?? 5000,
      ...(config.restore ? { restore: config.restore } : {}),
      onRecognizerFailure: (err) =>
        this.logger.warn('recognizer_failed_continuing', { error: err instanceof Error ? err.message : String(err) }),
    };
    this.logger = new Logger('vela-core', config.enableLogging ?? false);
    this.audit = config.audit;
    this.auditContext = { ...(config.keyId ? { key_id: config.keyId } : {}) };
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
