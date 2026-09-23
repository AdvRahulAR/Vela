import { DEFAULT_FPE_TYPES, DEFAULT_TOKEN_TYPES } from '../config/constants.js';
import { detectPii } from './detector.js';
import { FpeMasker } from './fpe.js';
import { TokenMasker } from './tokens.js';
import { TokenStreamDeMasker } from './streaming.js';
import { Logger } from '../utils/logger.js';
import { QuantumKeyManager } from './quantum.js';
import type {
  CustomDetector,
  EntityType,
  MaskResult,
  UnmaskResult,
  VelaConfig,
} from '../types.js';

/**
 * Vela — Universal LLM Privacy Gateway
 * Orchestrates NIST SP 800-38G FF1 FPE for structured IDs,
 * semantic tokenization for soft PII, and post-quantum keys.
 */
export class Vela {
  private fpe: FpeMasker;
  private glossary: string[];
  private fpeTypes: EntityType[];
  private tokenTypes: EntityType[];
  private validateChecksums: boolean;
  private customDetectors: CustomDetector[];
  private logger: Logger;

  constructor(config: VelaConfig = {}) {
    let key = config.fpeKey;
    if (!key) {
      const kp = QuantumKeyManager.generateKeyPair();
      const { sharedSecret } = QuantumKeyManager.encapsulate(kp.publicKey);
      key = QuantumKeyManager.deriveFpeKey(sharedSecret);
    }

    this.fpe = new FpeMasker(key, config.fpeTweak);
    this.glossary = config.glossary ?? [];
    this.fpeTypes = config.fpeTypes ?? DEFAULT_FPE_TYPES;
    this.tokenTypes = config.tokenTypes ?? DEFAULT_TOKEN_TYPES;
    this.validateChecksums = config.validateChecksums ?? true;
    this.customDetectors = config.customDetectors ?? [];
    this.logger = new Logger('vela-core', config.enableLogging ?? false);
  }

  /**
   * Mask PII in text. Returns masked text + maps for de-masking.
   */
  mask(text: string): MaskResult {
    const startTime = Date.now();
    const entities = detectPii(text, {
      glossary: this.glossary,
      validateChecksums: this.validateChecksums,
      customDetectors: this.customDetectors,
    });

    const fpeEntities = [];
    const tokenEntities = [];

    for (const e of entities) {
      if (this.fpeTypes.includes(e.type) && FpeMasker.isStructured(e.type)) {
        fpeEntities.push(e);
      } else if (this.tokenTypes.includes(e.type)) {
        tokenEntities.push(e);
      }
    }

    // Step 1: Encrypt structured IDs with FPE (from right to left to keep indices stable)
    let fpeText = text;
    const fpeMap: Record<string, string> = {};
    const fpeSorted = [...fpeEntities].sort((a, b) => b.start - a.start);

    for (const e of fpeSorted) {
      const original = text.slice(e.start, e.end);
      const cipher = this.fpe.encrypt(original);
      if (cipher) {
        fpeText = fpeText.slice(0, e.start) + cipher + fpeText.slice(e.end);
        fpeMap[original] = cipher;
      }
    }

    // Step 2: Mask soft PII entities with semantic tokens using an isolated session masker
    const tokens = new TokenMasker();
    const tokenResult = tokens.mask(fpeText, tokenEntities);

    const elapsed = Date.now() - startTime;
    this.logger.info(
      'mask',
      {
        entitiesDetected: entities.length,
        fpeCount: Object.keys(fpeMap).length,
        tokenCount: Object.keys(tokenResult.mapping).length,
      },
      elapsed
    );

    return {
      text: tokenResult.text,
      mapping: tokenResult.mapping,
      fpeMap,
      entities,
    };
  }

  /**
   * De-mask an LLM response using the MaskResult from mask().
   */
  unmask(text: string, result: MaskResult | MaskResult[]): UnmaskResult {
    const startTime = Date.now();
    let out = text;
    let restored = 0;

    const results = Array.isArray(result) ? result : [result];

    const pairs: Array<{ target: string; replacement: string }> = [];
    for (const res of results) {
      for (const [token, original] of Object.entries(res.mapping)) {
        pairs.push({ target: token, replacement: original });
      }
      for (const [original, cipher] of Object.entries(res.fpeMap)) {
        pairs.push({ target: cipher, replacement: original });
      }
    }
    // Sort longest target first to prevent substring collision during replacement
    pairs.sort((a, b) => b.target.length - a.target.length);

    for (const { target, replacement } of pairs) {
      const count = out.split(target).length - 1;
      if (count > 0) {
        out = out.split(target).join(replacement);
        restored += count;
      }
    }

    const elapsed = Date.now() - startTime;
    this.logger.info('unmask', { restored }, elapsed);

    return { text: out, restored };
  }

  /**
   * Create a streaming de-masker for real-time token/SSE stream unmasking.
   */
  createStreamDeMasker(result: MaskResult | MaskResult[]): TokenStreamDeMasker {
    return new TokenStreamDeMasker(result);
  }
}
