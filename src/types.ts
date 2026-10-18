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
  | 'MAC_ADDRESS'
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
  /**
   * Entity type of the matches. A type that is not one of the built-in
   * `StandardEntityType`s is always masked as a placeholder (`[MY_TYPE_1]`),
   * or with FPE if listed in `fpeTypes`; it never needs to be added to `tokenTypes`.
   */
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

/** A span found by a recognizer. Offsets are UTF-16 code units into the text (JavaScript string indices). */
export interface RecognizedSpan {
  type: EntityType;
  start: number;
  end: number;
  confidence?: number;
}

/**
 * An asynchronous, batched recognizer, typically a call to an NER service
 * (see `presidioRecognizer`). Receives every text of a request at once and
 * returns one array of spans per text, in the same order. Must honour `signal`.
 */
export type AsyncEntityRecognizer = (texts: string[], signal: AbortSignal) => Promise<RecognizedSpan[][]>;

export interface VelaConfig {
  /** 32-byte FPE key. If omitted, a random ephemeral key is generated per Vela instance. */
  fpeKey?: Uint8Array;
  /** Legacy tweak for the low-level FpeMasker.encrypt()/decrypt() API. Not used by mask(). */
  fpeTweak?: Uint8Array;
  /** Glossary of confidential terms/phrases to mask. */
  glossary?: string[];
  /**
   * Built-in entity types to mask using Format-Preserving Encryption.
   * Replaces `DEFAULT_FPE_TYPES` when set (it is not merged with the default list).
   */
  fpeTypes?: EntityType[];
  /**
   * Built-in entity types to mask using reversible placeholders such as `[EMAIL_1]`.
   * Replaces `DEFAULT_TOKEN_TYPES` when set. A built-in type listed in neither
   * `fpeTypes` nor `tokenTypes` is detected but left in clear text; custom types
   * (from `customDetectors` / `recognizers`) are always masked regardless.
   */
  tokenTypes?: EntityType[];
  /** Whether to enforce cryptographic checksum validation (e.g. Verhoeff, Luhn). Default: true. */
  validateChecksums?: boolean;
  /** Custom detectors to run alongside built-in detectors. */
  customDetectors?: CustomDetector[];
  /**
   * Async recognizers (NER services such as Presidio) run before masking. When
   * set, use `vela.maskAsync()` or the `*Async` request helpers; the proxy,
   * fetch interceptor, Express middleware and client wrappers do this for you.
   * Synchronous `mask()` throws `VelaNotPreparedError` on unprepared text.
   */
  asyncRecognizers?: AsyncEntityRecognizer[];
  /**
   * What to do when an async recognizer fails or times out. 'block' (default)
   * throws `VelaRecognizerError` (HTTP 503 in the proxy) and sends nothing
   * upstream. 'continue' falls back to built-in detection for that request.
   */
  recognizerFailure?: 'block' | 'continue';
  /** Timeout for one async recognizer call, in milliseconds. Default: 5000. */
  recognizerTimeoutMs?: number;
  /**
   * Detector packs to enable: 'pci' (CVV, expiry, track data), 'india-bfsi'
   * (CKYC, UAN, demat, CIN, DIN, TAN, LEI, MICR, SWIFT, vehicle registration),
   * 'health-in' (ABHA, MRN/UHID), 'us', 'eu-uk', 'intl'. See `DETECTOR_PACKS`.
   */
  packs?: string[];
  /** Extra recognizers (e.g. NER models) run alongside the built-in detectors. */
  recognizers?: EntityRecognizer[];
  /**
   * Built-in heuristic detection of person names (honorifics, "my name is …",
   * first-name gazetteer). Default: true.
   */
  detectNames?: boolean;
  /**
   * Mask party names inside court case citations ("State of Kerala v. Rahul
   * Sharma (2019) 3 SCC 123"). Default: false — reported citations are public
   * record and are left intact. Case titles without a reporter citation are
   * always masked.
   */
  maskCitationParties?: boolean;
  /**
   * Largest single text (one prompt, one JSON string field) that will be masked.
   * Larger input throws `VelaInputTooLargeError` (HTTP 413 in the proxy) rather
   * than tying up the event loop. Default: 2,000,000 characters.
   */
  maxInputChars?: number;
  /**
   * Whether placeholders in each part of a response are restored. Set
   * `toolArguments: 'placeholders'` when tool calls run automatically, so a
   * prompt-injected model can't put a real value into a tool call. Default:
   * everything restored.
   */
  restore?: import('./core/session.js').RestorePolicy;
  /**
   * Audit sink. The proxy, fetch interceptor and Express middleware send it a
   * value-free event before each request is forwarded and another when the
   * response completes (see `jsonlFileSink`). If the sink throws before
   * forwarding, the request is rejected (HTTP 503) and nothing is sent.
   */
  audit?: import('./core/audit.js').AuditSink;
  /**
   * Declarative masking policy (see `loadPolicy()` and `POLICY_PRESETS`):
   * per-entity actions (fpe, fpe-synthetic, token, redact, block, allow),
   * provider and model allowlists, non-text content, restore policy, NER
   * requirement and detector packs. Its id and hash go into audit events.
   */
  policy?: import('./core/policy.js').VelaPolicy;
  /**
   * Entity types your own recognizers (sync or async) can return, so a policy
   * may name them. Policy entries for any other unknown type are an error.
   */
  extraEntityTypes?: string[];
  /** Identifier of the FPE key, recorded in audit events (never the key itself). */
  keyId?: string;
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
  /**
   * Give a partial mention of a person ("Joseph", "Mr. Sharma", "SHARMA") the
   * same placeholder as the full name seen in the session ("Joseph Mathew",
   * "Rahul Sharma") when it matches exactly one known name. The partial mention
   * is restored as the full name. Default: true.
   */
  linkPartialNames?: boolean;
}

export interface Replacement {
  /** What the LLM sees. */
  masked: string;
  /** The real value. */
  original: string;
  type: EntityType;
  /** 'redact' placeholders are never restored. */
  method: 'fpe' | 'token' | 'redact';
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
  /**
   * Routes on a known provider host that Vela can't mask (batches, files,
   * unknown endpoints): 'safe' (default) throws `VelaRouteBlockedError`;
   * 'all' sends them unmasked.
   */
  passthrough?: 'safe' | 'all';
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
  /**
   * Routes Vela cannot mask:
   * - 'safe' (default): body-free requests (GET /v1/models, DELETE …) are forwarded;
   *   any other route Vela can't mask (batches, files, audio, unknown endpoints) gets 403.
   * - 'none' (or `false`): only maskable routes are served; everything else gets 404.
   * - 'all' (or `true`): unknown routes are forwarded **unmasked**. Opt in only if you accept that.
   * Chat, Responses, Messages, count_tokens, embeddings, moderations and legacy
   * completions are always masked.
   */
  passthrough?: boolean | 'safe' | 'all' | 'none';
  /**
   * Client tokens, mapped to a tenant name. Clients send `x-vela-key: <token>`;
   * the tenant is recorded in audit events and bound into session ids. Required
   * to listen beyond loopback (unless `insecure`).
   */
  authTokens?: Record<string, string>;
  /** Allow a non-loopback `host` without `authTokens` (only behind something that authenticates). */
  insecure?: boolean;
  /** Requests per minute per tenant (or client IP without auth). Excess gets HTTP 429. */
  rateLimitPerMinute?: number;
  /**
   * Serve Prometheus metrics (counts only) at `GET /metrics`. Default: true.
   * `/metrics`, `/health` and `/readyz` don't need a client token.
   */
  metrics?: boolean;
  /** Serve HTTPS with this certificate and key (PEM). */
  tls?: { cert: string | Buffer; key: string | Buffer };
}
