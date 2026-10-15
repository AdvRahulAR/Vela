/**
 * Core types for Vela Privacy Gateway
 */

export type StandardEntityType =
  | 'AADHAAR'
  | 'PAN'
  | 'GSTIN'
  | 'CREDIT_CARD'
  | 'EMAIL'
  | 'PHONE'
  | 'SSN'
  | 'IBAN'
  | 'IP_ADDRESS'
  | 'BANK_ACCOUNT'
  | 'IFSC'
  | 'PASSPORT'
  | 'VOTER_ID'
  | 'DRIVING_LICENCE'
  | 'UPI_ID'
  | 'DATE_OF_BIRTH'
  | 'PIN_CODE'
  | 'ADDRESS'
  | 'SECRET_KEY'
  | 'JWT'
  | 'PERSON'
  | 'LOCATION'
  | 'ORG'
  | 'CUSTOM';

export type EntityType = StandardEntityType | (string & {});

export interface DetectedEntity {
  type: EntityType;
  start: number;
  end: number;
  value: string;
  confidence: number;
  metadata?: Record<string, unknown>;
}

export interface CustomDetector {
  name: string;
  type: EntityType;
  regex: RegExp;
  confidence?: number;
  validator?: (match: string) => boolean;
}

/**
 * A pluggable entity recognizer (e.g. a wrapper around an NER model such as
 * spaCy, Presidio, compromise or wink-nlp). Must be synchronous; return spans
 * with start/end offsets into `text`.
 */
export type EntityRecognizer = (
  text: string,
) => Array<{ type: EntityType; start: number; end: number; confidence?: number }>;

export interface VelaConfig {
  /** 32-byte FPE key. If omitted, a random ephemeral key is generated per Vela instance. */
  fpeKey?: Uint8Array;
  /** Legacy tweak for the low-level FpeMasker.encrypt()/decrypt() API. Not used by mask(). */
  fpeTweak?: Uint8Array;
  /** Glossary of confidential terms/phrases to mask. */
  glossary?: string[];
  /** Entity types to mask using Format-Preserving Encryption. */
  fpeTypes?: EntityType[];
  /** Entity types to mask using reversible semantic tokens. */
  tokenTypes?: EntityType[];
  /** Whether to enforce cryptographic checksum validation (e.g. Verhoeff, Luhn). Default: true. */
  validateChecksums?: boolean;
  /** Custom detectors to run alongside built-in detectors. */
  customDetectors?: CustomDetector[];
  /** Extra recognizers (e.g. NER models) run alongside the built-in detectors. */
  recognizers?: EntityRecognizer[];
  /**
   * Built-in heuristic detection of person names (honorifics, "my name is …",
   * first-name gazetteer). Default: true.
   */
  detectNames?: boolean;
  /** Enable structured JSON logging. Default: false. */
  enableLogging?: boolean;
}

export interface SessionOptions {
  /**
   * Stable conversation/session identifier. When set, the same value masks to
   * the same ciphertext for every request carrying this id (keeps provider
   * prompt-caching and server-side conversation state working). When omitted,
   * a random per-session tweak is used so masked values cannot be linked
   * across sessions.
   */
  sessionId?: string;
}

export interface Replacement {
  /** What the LLM sees. */
  masked: string;
  /** The real value. */
  original: string;
  type: EntityType;
  method: 'fpe' | 'token';
}

export interface MaskResult {
  text: string;
  /** Token placeholder -> original value (for token-masked entities). */
  mapping: Record<string, string>;
  /** Original value -> FPE ciphertext. */
  fpeMap: Record<string, string>;
  /** Entities detected during masking. */
  entities: DetectedEntity[];
  /** Full replacement records (masked <-> original, type, method). */
  replacements?: Replacement[];
}

export interface UnmaskResult {
  text: string;
  restored: number;
}

export interface StreamDeMasker {
  feed(chunk: string): string;
  flush(): string;
}

/**
 * OpenAI chat completion schema definitions
 */
export interface OpenAITextContentPart {
  type: 'text';
  text: string;
}

export interface OpenAIImageContentPart {
  type: 'image_url';
  image_url: {
    url: string;
    detail?: 'auto' | 'low' | 'high';
  };
}

export type OpenAIContentPart = OpenAITextContentPart | OpenAIImageContentPart | Record<string, unknown>;

export interface OpenAIToolCall {
  id?: string;
  type?: 'function';
  function?: {
    name?: string;
    arguments?: string;
  };
}

export interface OpenAIMessage {
  role: 'system' | 'user' | 'assistant' | 'tool' | 'function' | string;
  content?: string | OpenAIContentPart[] | null;
  name?: string;
  tool_calls?: OpenAIToolCall[];
  [key: string]: unknown;
}

export interface OpenAIRequest {
  messages: OpenAIMessage[];
  stream?: boolean;
  model?: string;
  temperature?: number;
  [key: string]: unknown;
}

export interface OpenAIChoice {
  index?: number;
  message?: OpenAIMessage;
  delta?: {
    role?: string;
    content?: string | null;
    tool_calls?: OpenAIToolCall[];
  };
  finish_reason?: string | null;
  [key: string]: unknown;
}

export interface OpenAIResponse {
  id?: string;
  object?: string;
  created?: number;
  model?: string;
  choices?: OpenAIChoice[];
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
  [key: string]: unknown;
}

export type LlmApiFormat = 'openai-chat' | 'openai-responses' | 'anthropic-messages';

export interface FetchInterceptorOptions {
  providers?: string[];
  targetUrls?: string[];
  /** Resolve a stable session id for a request (alternatively send an `x-vela-session` header). */
  sessionId?: (url: string, init?: RequestInit) => string | undefined;
}

export interface ExpressMiddlewareOptions {
  upstream?: string;
  /** Upstream API key. Sent as `Authorization: Bearer` (OpenAI) or `x-api-key` (Anthropic). */
  apiKey?: string;
}

export interface ProxyServerOptions {
  port?: number;
  /** Interface to bind. Default: 127.0.0.1 (loopback only). Use 0.0.0.0 to expose deliberately. */
  host?: string;
  upstream?: string;
  /** Upstream API key. Sent as `Authorization: Bearer` (OpenAI) or `x-api-key` (Anthropic). */
  apiKey?: string;
  maxBodySizeBytes?: number;
  /** Forward non-chat routes (/v1/models, /v1/embeddings…) upstream. Default: true. Set false to 404 them. */
  passthrough?: boolean;
}
