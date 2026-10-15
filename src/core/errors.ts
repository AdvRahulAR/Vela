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
