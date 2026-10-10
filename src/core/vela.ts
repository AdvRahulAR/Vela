import { randomBytes } from 'node:crypto';
import { DEFAULT_FPE_TYPES, DEFAULT_TOKEN_TYPES } from '../config/constants.js';
import { FpeMasker } from './fpe.js';
import { MaskSession, type SessionEngine } from './session.js';
import { Restorer, replacementsFrom, type RestoreOptions, type StreamRestorer } from './matcher.js';
import { Logger } from '../utils/logger.js';
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
      },
    };
    this.logger = new Logger('vela-core', config.enableLogging ?? false);
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
