// Core
export { Vela } from './core/vela.js';
export {
  VelaError,
  VelaInputTooLargeError,
  VelaRecognizerError,
  VelaNotPreparedError,
  VelaRouteBlockedError,
} from './core/errors.js';
export { MaskSession } from './core/session.js';
export { FF1 } from './core/ff1.js';
export { FpeMasker, STRUCTURED_TYPES } from './core/fpe.js';
export { TokenMasker } from './core/tokens.js';
export { QuantumKeyManager } from './core/quantum.js';
export { Restorer, StreamRestorer, replacementsFrom } from './core/matcher.js';
export {
  TokenStreamDeMasker,
  createSseDeMasker,
  createSseTransformer,
  createEventUnmasker,
  OpenAiChatStreamUnmasker,
  AnthropicStreamUnmasker,
  ResponsesStreamUnmasker,
} from './core/streaming.js';
export { detectPii, type DetectOptions } from './core/detector.js';

// Algorithms
export { validateVerhoeff, generateVerhoeffChecksum } from './core/algorithms/verhoeff.js';
export { validateLuhn, luhnCheckDigit } from './core/algorithms/luhn.js';
export { validateIban } from './core/algorithms/iban.js';
export { validateGstin, gstinCheckChar } from './core/algorithms/gstin.js';

// Integrations
export {
  maskOpenAiRequest,
  maskOpenAiRequestAsync,
  maskOpenAiResponsesRequest,
  maskOpenAiResponsesRequestAsync,
  unmaskOpenAiResponse,
  unmaskOpenAiStream,
  unmaskOpenAiResponsesStream,
  wrapOpenAiClient,
  type WrapClientOptions,
} from './integrations/openai.js';
export {
  maskAnthropicRequest,
  maskAnthropicRequestAsync,
  unmaskAnthropicResponse,
  unmaskAnthropicStream,
  wrapAnthropicClient,
} from './integrations/anthropic.js';
export {
  detectApiFormat,
  classifyRoute,
  maskLlmRequest,
  maskLlmRequestAsync,
  maskFieldsAsync,
  type RouteClass,
} from './integrations/formats.js';
export { presidioRecognizer, codePointToUtf16Index, type PresidioRecognizerOptions } from './integrations/presidio.js';
export { forwardLlmRequest, forwardFieldsRequest } from './integrations/gateway.js';
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
  DEFAULT_PROXY_HOST,
  DEFAULT_UPSTREAM_URL,
  DEFAULT_ANTHROPIC_URL,
  SESSION_HEADER,
} from './config/constants.js';

// Types
export type {
  EntityType,
  StandardEntityType,
  DetectedEntity,
  CustomDetector,
  EntityRecognizer,
  AsyncEntityRecognizer,
  RecognizedSpan,
  VelaConfig,
  SessionOptions,
  Replacement,
  MaskResult,
  UnmaskResult,
  StreamDeMasker,
  LlmApiFormat,
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

export type { KeyPair, EncapsulationResult, SealedKey } from './core/quantum.js';
