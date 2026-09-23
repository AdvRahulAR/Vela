// Core classes and engines
export { Vela } from './core/vela.js';
export { FpeMasker } from './core/fpe.js';
export { TokenMasker } from './core/tokens.js';
export { QuantumKeyManager } from './core/quantum.js';
export { TokenStreamDeMasker, createSseDeMasker } from './core/streaming.js';
export { detectPii } from './core/detector.js';

// Algorithms
export { validateVerhoeff, generateVerhoeffChecksum } from './core/algorithms/verhoeff.js';
export { validateLuhn } from './core/algorithms/luhn.js';
export { validateIban } from './core/algorithms/iban.js';

// Integrations
export {
  maskOpenAiRequest,
  unmaskOpenAiResponse,
  unmaskOpenAiStream,
  wrapOpenAiClient,
} from './integrations/openai.js';
export { createFetchInterceptor } from './integrations/fetch.js';
export { createExpressMiddleware } from './integrations/express.js';
export { runProxy } from './integrations/proxy.js';

// Observability
export { Logger } from './utils/logger.js';

// Constants
export {
  DIGITS,
  UPPER_ALNUM,
  LOWER_ALNUM,
  MIXED_ALNUM,
  DEFAULT_FPE_TYPES,
  DEFAULT_TOKEN_TYPES,
  DEFAULT_PROXY_PORT,
  DEFAULT_UPSTREAM_URL,
} from './config/constants.js';

// Types
export type {
  EntityType,
  StandardEntityType,
  DetectedEntity,
  CustomDetector,
  VelaConfig,
  MaskResult,
  UnmaskResult,
  StreamDeMasker,
  OpenAIMessage,
  OpenAIRequest,
  OpenAIResponse,
  OpenAIChoice,
  OpenAIContentPart,
  OpenAITextContentPart,
  OpenAIImageContentPart,
  OpenAIToolCall,
  FetchInterceptorOptions,
  ExpressMiddlewareOptions,
  ProxyServerOptions,
} from './types.js';

export type {
  KeyPair,
  EncapsulationResult,
  SealedKey,
} from './core/quantum.js';
