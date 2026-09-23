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
  | 'CASE_ID'
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

export interface VelaConfig {
  /** 32-byte FPE key — if omitted, derived from ML-KEM-768 shared secret. */
  fpeKey?: Uint8Array;
  /** Custom tweak for FPE (default 8-byte zero tweak for deterministic per-session masking). */
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
  /** Enable structured JSON logging. Default: false. */
  enableLogging?: boolean;
}

export interface MaskResult {
  text: string;
  /** Token placeholder -> original value (for token-masked entities). */
  mapping: Record<string, string>;
  /** Original value -> FPE ciphertext. */
  fpeMap: Record<string, string>;
  /** Entities detected during masking. */
  entities: DetectedEntity[];
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

export interface FetchInterceptorOptions {
  providers?: string[];
  targetUrls?: string[];
}

export interface ExpressMiddlewareOptions {
  upstream?: string;
  apiKey?: string;
}

export interface ProxyServerOptions {
  port?: number;
  upstream?: string;
  apiKey?: string;
  maxBodySizeBytes?: number;
}
