/**
 * Typed errors. Integrations map `status` to an HTTP response and never forward
 * a request upstream after one of these is thrown (fail closed).
 */
export class VelaError extends Error {
  /** HTTP status the proxy / Express middleware should return. */
  readonly status: number;
  constructor(message: string, status = 500) {
    super(message);
    this.name = new.target.name;
    this.status = status;
  }
}

/** A single text exceeded `VelaConfig.maxInputChars`. */
export class VelaInputTooLargeError extends VelaError {
  constructor(length: number, limit: number) {
    super(`Input of ${length} characters exceeds maxInputChars (${limit})`, 413);
  }
}

/**
 * An async recognizer (NER service) failed or timed out while
 * `recognizerFailure` is 'block'. Nothing was sent upstream.
 */
export class VelaRecognizerError extends VelaError {
  readonly cause: unknown;
  constructor(cause: unknown) {
    const why = cause instanceof Error ? cause.message : String(cause);
    super(`PII recognizer unavailable; request not forwarded (${why})`, 503);
    this.cause = cause;
  }
}

/**
 * mask() was called on text that has not been through prepare() while async
 * recognizers are configured. Use maskAsync() / the *Async helpers, or call
 * `await session.prepare(texts)` first.
 */
export class VelaNotPreparedError extends VelaError {
  constructor() {
    super(
      'Async recognizers are configured: use vela.maskAsync(), the *Async request helpers, or await session.prepare() before mask()',
      500,
    );
  }
}
